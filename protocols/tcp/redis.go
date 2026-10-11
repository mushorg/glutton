package tcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/redis"
)

// The command set follows what attackers send to exposed Redis, as catalogued
// by RedisHoneyPot (https://github.com/cypwnpwnsocute/RedisHoneyPot, GPL-3.0;
// no code was taken from it): the cron/SSH-key write chain (FLUSHALL, SET,
// CONFIG SET dir/dbfilename, SAVE), rogue-master replication (SLAVEOF,
// MODULE LOAD) and recon (INFO, CONFIG GET, KEYS). Replies are RESP2 as sent
// by an unauthenticated Redis 5.0.7, the Ubuntu 20.04 package.

const (
	// maxRedisCommands bounds a session; the write chains are ~10 commands.
	maxRedisCommands = 64
	// maxRedisKeys bounds the per-connection keyspace.
	maxRedisKeys = 64
	// maxRedisDecodedArgs and maxRedisArgLen bound the args summary in a
	// read frame; payload always holds the full request.
	maxRedisDecodedArgs = 32
	maxRedisArgLen      = 256
)

type parsedRedis struct {
	Direction string   `json:"direction,omitempty"` // "read" (from attacker) or "write" (from honeypot)
	Command   string   `json:"command,omitempty"`   // lowercased command; "config set" for container commands
	Args      []string `json:"args,omitempty"`      // arguments after the command, capped
	Path      string   `json:"path,omitempty"`      // CONFIG SET dir/dbfilename value, MODULE LOAD path
	Status    string   `json:"status,omitempty"`    // OK / PONG / ERR / bulk / nil / integer / array on writes
	Payload   []byte   `json:"payload,omitempty"`   // raw bytes as seen on the wire
	Truncated bool     `json:"truncated,omitempty"` // the request passed the read cap or was cut off
	Inline    bool     `json:"inline,omitempty"`    // sent as a plain text line, not a RESP array
	// SLAVEOF / REPLICAOF target as host:port; it is never dialed
	Master string `json:"master,omitempty"`
	// AUTH, HELLO AUTH and MIGRATE AUTH credentials, and the CONFIG SET
	// requirepass/masterauth value; guessing attempts, recorded as sent
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// redisPersona is the server identity shown in INFO; tests replace it.
type redisPersona struct {
	RunID   string
	ReplID  string
	PID     int
	Started time.Time
}

func newRedisPersona() redisPersona {
	return redisPersona{
		RunID:   randomHex(20),
		ReplID:  randomHex(20),
		PID:     600 + mrand.IntN(2400),
		Started: time.Now().Add(-time.Duration(7+mrand.IntN(60))*24*time.Hour - time.Duration(mrand.IntN(86400))*time.Second),
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var (
	redisInstance = newRedisPersona()
	redisNow      = time.Now
	redisClientID atomic.Int64
)

func init() {
	redisClientID.Store(int64(100 + mrand.IntN(5000)))
}

// redisContainers are commands whose first argument is the leaf operation.
var redisContainers = map[string]bool{
	"config": true, "client": true, "module": true, "command": true, "script": true,
	"cluster": true, "debug": true, "memory": true, "object": true, "slowlog": true,
	"acl": true, "pubsub": true, "xinfo": true,
}

// redisArity is the Redis 5 command table arity: n is an exact argument
// count (name included), -n a minimum.
var redisArity = map[string]int{
	"ping": -1, "echo": 2, "info": -1, "time": 1, "auth": 2, "select": 2,
	"get": 2, "set": -3, "del": -2, "unlink": -2, "exists": -2, "keys": 2,
	"scan": -2, "dbsize": 1, "type": 2, "ttl": 2, "expire": 3,
	"flushall": -1, "flushdb": -1, "save": 1, "bgsave": -1, "bgrewriteaof": 1,
	"lastsave": 1, "config": -2, "client": -2, "module": -2, "command": -1,
	"slaveof": 3, "replicaof": 3, "eval": -3, "evalsha": -3, "shutdown": -1,
}

// redisConfigOrder is the CONFIG GET order of the emulated parameters.
var redisConfigOrder = []string{
	"dbfilename", "requirepass", "masterauth", "logfile", "pidfile", "dir",
	"bind", "port", "protected-mode", "databases", "maxmemory", "maxmemory-policy",
	"maxclients", "timeout", "tcp-keepalive", "daemonize", "loglevel", "save",
	"appendonly", "appendfilename", "slave-read-only", "replica-read-only",
}

func redisDefaultConfig(port uint16) map[string]string {
	return map[string]string{
		"dbfilename": "dump.rdb", "requirepass": "", "masterauth": "",
		"logfile": "/var/log/redis/redis-server.log", "pidfile": "/var/run/redis/redis-server.pid",
		"dir": "/var/lib/redis", "bind": "0.0.0.0", "port": strconv.Itoa(int(port)),
		"protected-mode": "no", "databases": "16", "maxmemory": "0", "maxmemory-policy": "noeviction",
		"maxclients": "10000", "timeout": "0", "tcp-keepalive": "300", "daemonize": "yes",
		"loglevel": "notice", "save": "900 1 300 10 60 10000", "appendonly": "no",
		"appendfilename": "appendonly.aof", "slave-read-only": "yes", "replica-read-only": "yes",
	}
}

type redisServer struct {
	events     []parsedRedis
	conn       net.Conn
	reader     *bufio.Reader
	port       uint16
	keys       map[string][]byte
	config     map[string]string
	master     string // host:port after SLAVEOF, "" while master
	clientID   int64
	clientName string
	dirty      int
	commands   int
	lastSave   time.Time
}

func newRedisServer(conn net.Conn, port uint16) *redisServer {
	return &redisServer{
		events:   []parsedRedis{},
		conn:     conn,
		reader:   bufio.NewReader(conn),
		port:     port,
		keys:     map[string][]byte{},
		config:   redisDefaultConfig(port),
		clientID: redisClientID.Add(1),
		lastSave: redisInstance.Started,
	}
}

func (s *redisServer) write(r redis.Reply) error {
	if _, err := s.conn.Write(r.Data); err != nil {
		return err
	}
	s.events = append(s.events, parsedRedis{Direction: "write", Status: r.Status, Payload: r.Data})
	return nil
}

// HandleRedis takes a net.Conn and emulates an unauthenticated Redis server.
// It never connects to a SLAVEOF target and never loads modules or runs
// scripts.
func HandleRedis(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := newRedisServer(conn, md.TargetPort)
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("redis", conn, md, helpers.FirstOrEmpty[parsedRedis](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "redis"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Redis connection", slog.String("protocol", "redis"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	for i := 0; ; i++ {
		if i == maxRedisCommands {
			endReason = connection.EndMaxFrames
			return nil
		}
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "redis"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}

		cmd, err := redis.ReadCommand(server.reader, redis.MaxRequestLen)
		if err != nil {
			if len(cmd.Raw) > 0 {
				server.events = append(server.events, parsedRedis{
					Direction: "read", Command: cmd.Name(), Payload: cmd.Raw, Inline: cmd.Inline, Truncated: true,
				})
			}
			endReason = server.readFailed(cmd, err, logger)
			return nil
		}

		f := parsedRedis{Direction: "read", Payload: cmd.Raw, Inline: cmd.Inline}
		if len(cmd.Args) == 0 {
			// blank lines and empty arrays get no reply
			server.events = append(server.events, f)
			continue
		}
		if server.commands == 0 {
			logger.Info(
				"Redis command",
				slog.String("handler", "redis"),
				slog.String("dest_port", strconv.Itoa(int(md.TargetPort))),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.String("command", cmd.Name()),
			)
		}
		server.commands++
		reply, quit := server.exec(cmd, &f)
		server.events = append(server.events, f)
		if reply.Data != nil {
			if err := server.write(reply); err != nil {
				logger.Error("Failed to write Redis reply", slog.String("protocol", "redis"), producer.ErrAttr(err))
				endReason = connection.EndWriteError
				return nil
			}
		}
		if quit {
			return nil
		}
	}
}

// readFailed answers a malformed or oversize request like the server does
// and returns the session end reason.
func (s *redisServer) readFailed(cmd redis.Command, err error, logger interfaces.Logger) string {
	var pe *redis.ProtocolError
	switch {
	case errors.As(err, &pe):
	case errors.Is(err, redis.ErrTooLong):
		pe = &redis.ProtocolError{Msg: "invalid bulk length"}
		if cmd.Inline {
			pe.Msg = "too big inline request"
		}
	default:
		logger.Debug("Failed to read data", slog.String("protocol", "redis"), producer.ErrAttr(err))
		return connection.EndReasonFromRead(err)
	}
	logger.Debug("Invalid Redis request", slog.String("protocol", "redis"), producer.ErrAttr(err))
	if werr := s.write(redis.ProtocolErrorReply(pe)); werr != nil {
		return connection.EndWriteError
	}
	return connection.EndReadError
}

// exec annotates the read frame f and returns the reply; quit closes the
// connection after the reply is sent. A nil reply sends nothing.
func (s *redisServer) exec(cmd redis.Command, f *parsedRedis) (reply redis.Reply, quit bool) {
	name := cmd.Name()
	args := cmd.Args[1:]
	f.Command = name
	sub := ""
	if redisContainers[name] && len(args) > 0 {
		sub = strings.ToLower(string(args[0]))
		f.Command = name + " " + sub
		f.Args = redisDecodedArgs(args[1:])
	} else {
		f.Args = redisDecodedArgs(args)
	}

	switch name {
	case "quit":
		return redis.Simple("OK"), true
	case "post", "host:":
		// cross-protocol scripting guard: the server logs a security attack
		// and drops the connection without a reply
		return redis.Reply{}, true
	}
	arity, known := redisArity[name]
	if !known {
		if name == "hello" || name == "migrate" {
			redisAuthArgs(f, args)
		}
		return redis.UnknownCommand(cmd.Args), false
	}
	if n := len(cmd.Args); (arity > 0 && n != arity) || (arity < 0 && n < -arity) {
		if name == "auth" && len(args) == 2 {
			// AUTH user pass is Redis 6 syntax; 5.0 rejects the arity
			f.Username, f.Password = string(args[0]), string(args[1])
		}
		return redis.WrongArity(name), false
	}

	switch name {
	case "ping":
		switch len(args) {
		case 0:
			return redis.Simple("PONG"), false
		case 1:
			return redis.Bulk(args[0]), false
		}
		return redis.WrongArity(name), false
	case "echo":
		return redis.Bulk(args[0]), false
	case "time":
		now := redisNow()
		return redis.Array(strconv.FormatInt(now.Unix(), 10), strconv.Itoa(now.Nanosecond()/1000)), false
	case "info":
		section := "default"
		if len(args) > 0 {
			section = strings.ToLower(string(args[0]))
		}
		return redis.Bulk([]byte(s.info(section))), false
	case "auth":
		f.Password = string(args[0])
		pass := s.config["requirepass"]
		switch {
		case pass == "":
			return redis.Error("ERR Client sent AUTH, but no password is set"), false
		case string(args[0]) != pass:
			return redis.Error("ERR invalid password"), false
		}
		return redis.Simple("OK"), false
	case "select":
		db, err := strconv.Atoi(string(args[0]))
		switch {
		case err != nil:
			return redis.Error("ERR invalid DB index"), false
		case db < 0 || db >= 16:
			return redis.Error("ERR DB index is out of range"), false
		}
		return redis.Simple("OK"), false
	case "get":
		v, ok := s.keys[string(args[0])]
		if !ok {
			return redis.Nil(), false
		}
		return redis.Bulk(v), false
	case "set":
		return s.set(args), false
	case "del", "unlink":
		n := 0
		for _, k := range args {
			if _, ok := s.keys[string(k)]; ok {
				delete(s.keys, string(k))
				n++
			}
		}
		s.dirty += n
		return redis.Integer(int64(n)), false
	case "exists":
		n := 0
		for _, k := range args {
			if _, ok := s.keys[string(k)]; ok {
				n++
			}
		}
		return redis.Integer(int64(n)), false
	case "keys":
		return redis.Array(s.matchKeys(string(args[0]))...), false
	case "scan":
		if _, err := strconv.ParseUint(string(args[0]), 10, 64); err != nil {
			return redis.Error("ERR invalid cursor"), false
		}
		pattern := "*"
		for i := 1; i+1 < len(args); i += 2 {
			if strings.EqualFold(string(args[i]), "match") {
				pattern = string(args[i+1])
			}
		}
		return redis.Scan("0", s.matchKeys(pattern)), false
	case "dbsize":
		return redis.Integer(int64(len(s.keys))), false
	case "type":
		if _, ok := s.keys[string(args[0])]; ok {
			return redis.Simple("string"), false
		}
		return redis.Simple("none"), false
	case "ttl":
		if _, ok := s.keys[string(args[0])]; ok {
			return redis.Integer(-1), false
		}
		return redis.Integer(-2), false
	case "expire":
		if _, err := strconv.ParseInt(string(args[1]), 10, 64); err != nil {
			return redis.Error("ERR value is not an integer or out of range"), false
		}
		if _, ok := s.keys[string(args[0])]; ok {
			return redis.Integer(1), false
		}
		return redis.Integer(0), false
	case "flushall", "flushdb":
		s.dirty += len(s.keys)
		clear(s.keys)
		return redis.Simple("OK"), false
	case "save":
		s.save()
		return redis.Simple("OK"), false
	case "bgsave":
		s.save()
		return redis.Simple("Background saving started"), false
	case "bgrewriteaof":
		return redis.Simple("Background append only file rewriting started"), false
	case "lastsave":
		return redis.Integer(s.lastSave.Unix()), false
	case "config":
		return s.configCmd(sub, args[1:], f), false
	case "client":
		return s.clientCmd(sub, args[1:]), false
	case "module":
		return s.moduleCmd(sub, args[1:], f), false
	case "command":
		switch sub {
		case "":
			return redis.Array(), false
		case "count":
			return redis.Integer(200), false
		}
		return redis.UnknownSubcommand(name, sub), false
	case "slaveof", "replicaof":
		return s.replicaOf(args, f), false
	case "eval":
		return redisEvalError(args[0]), false
	case "evalsha":
		return redis.Error("NOSCRIPT No matching script. Please use EVAL."), false
	case "shutdown":
		return redis.Reply{}, true
	}
	return redis.UnknownCommand(cmd.Args), false
}

// redisDecodedArgs is the capped args summary of a read frame.
func redisDecodedArgs(args [][]byte) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(args), maxRedisDecodedArgs))
	for _, a := range args[:min(len(args), maxRedisDecodedArgs)] {
		out = append(out, string(a[:min(len(a), maxRedisArgLen)]))
	}
	return out
}

// redisAuthArgs records the credentials of HELLO ... AUTH user pass and
// MIGRATE ... AUTH pass / AUTH2 user pass, both unknown to Redis 5.
func redisAuthArgs(f *parsedRedis, args [][]byte) {
	for i, a := range args {
		rest := args[i+1:]
		switch strings.ToLower(string(a)) {
		case "auth":
			if f.Command == "hello" && len(rest) >= 2 {
				f.Username, f.Password = string(rest[0]), string(rest[1])
			} else if f.Command == "migrate" && len(rest) >= 1 {
				f.Password = string(rest[0])
			}
		case "auth2":
			if len(rest) >= 2 {
				f.Username, f.Password = string(rest[0]), string(rest[1])
			}
		}
	}
}

func (s *redisServer) set(args [][]byte) redis.Reply {
	key := string(args[0])
	_, exists := s.keys[key]
	for i := 2; i < len(args); i++ {
		switch strings.ToLower(string(args[i])) {
		case "nx":
			if exists {
				return redis.Nil()
			}
		case "xx":
			if !exists {
				return redis.Nil()
			}
		case "ex", "px":
			i++
			if i == len(args) {
				return redis.Error("ERR syntax error")
			}
			if _, err := strconv.ParseInt(string(args[i]), 10, 64); err != nil {
				return redis.Error("ERR value is not an integer or out of range")
			}
		default:
			return redis.Error("ERR syntax error")
		}
	}
	// past the keyspace cap the write is acknowledged but not kept
	if exists || len(s.keys) < maxRedisKeys {
		s.keys[key] = slices.Clone(args[1])
	}
	s.dirty++
	return redis.Simple("OK")
}

func (s *redisServer) save() {
	s.lastSave = redisNow()
	s.dirty = 0
}

// matchKeys returns the keys matching a glob pattern, sorted.
func (s *redisServer) matchKeys(pattern string) []string {
	var out []string
	for k := range s.keys {
		if ok, _ := path.Match(pattern, k); ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

func (s *redisServer) configCmd(sub string, args [][]byte, f *parsedRedis) redis.Reply {
	switch {
	case sub == "get" && len(args) == 1:
		pattern := strings.ToLower(string(args[0]))
		var out []string
		for _, k := range redisConfigOrder {
			if ok, _ := path.Match(pattern, k); ok {
				out = append(out, k, s.config[k])
			}
		}
		return redis.Array(out...)
	case sub == "set" && len(args) == 2:
		param := strings.ToLower(string(args[0]))
		if _, ok := s.config[param]; !ok {
			return redis.Error("ERR Unsupported CONFIG parameter: " + string(args[0]))
		}
		value := string(args[1])
		switch param {
		case "dir", "dbfilename":
			f.Path = value
		case "requirepass", "masterauth":
			f.Password = value
		}
		// every write succeeds, so dir and dbfilename look writable
		s.config[param] = value
		return redis.Simple("OK")
	case (sub == "resetstat" || sub == "rewrite") && len(args) == 0:
		return redis.Simple("OK")
	}
	return redis.UnknownSubcommand("config", sub)
}

func (s *redisServer) clientCmd(sub string, args [][]byte) redis.Reply {
	switch {
	case sub == "setname" && len(args) == 1:
		if strings.ContainsAny(string(args[0]), " \r\n") {
			return redis.Error("ERR Client names cannot contain spaces, newlines or special characters.")
		}
		s.clientName = string(args[0])
		return redis.Simple("OK")
	case sub == "getname" && len(args) == 0:
		if s.clientName == "" {
			return redis.Nil()
		}
		return redis.Bulk([]byte(s.clientName))
	case sub == "id" && len(args) == 0:
		return redis.Integer(s.clientID)
	case sub == "list" && len(args) == 0:
		return redis.Bulk(fmt.Appendf(nil,
			"id=%d addr=%s fd=8 name=%s age=0 idle=0 flags=N db=0 sub=0 psub=0 multi=-1 qbuf=26 qbuf-free=32742 obl=0 oll=0 omem=0 events=r cmd=client\n",
			s.clientID, s.conn.RemoteAddr().String(), s.clientName))
	case sub == "kill":
		return redis.Error("ERR No such client")
	}
	return redis.UnknownSubcommand("client", sub)
}

func (s *redisServer) moduleCmd(sub string, args [][]byte, f *parsedRedis) redis.Reply {
	switch {
	case sub == "load" && len(args) >= 1:
		// rogue-master payloads (exp.so) end here; nothing is loaded
		f.Path = string(args[0])
		return redis.Error("ERR Error loading the extension. Please check the server logs.")
	case sub == "list" && len(args) == 0:
		return redis.Array()
	case sub == "unload" && len(args) == 1:
		return redis.Error("ERR Error unloading module: no such module with that name")
	}
	return redis.UnknownSubcommand("module", sub)
}

// replicaOf accepts SLAVEOF host port and records the target. The honeypot
// never dials it, so a rogue master never gets the PSYNC it waits for.
func (s *redisServer) replicaOf(args [][]byte, f *parsedRedis) redis.Reply {
	host, port := string(args[0]), string(args[1])
	if strings.EqualFold(host, "no") && strings.EqualFold(port, "one") {
		s.master = ""
		return redis.Simple("OK")
	}
	if _, err := strconv.ParseInt(port, 10, 64); err != nil {
		return redis.Error("ERR value is not an integer or out of range")
	}
	f.Master = net.JoinHostPort(host, port)
	s.master = f.Master
	return redis.Simple("OK")
}

// redisSandboxGlobals are the Lua globals the Redis 5 script sandbox does
// not define; CVE-2022-0543 payloads reach for package.loadlib.
var redisSandboxGlobals = regexp.MustCompile(`\b(package|io|os|require|loadfile|dofile)\b`)

// redisEvalError is the reply of a patched server to a script that escapes
// the sandbox; other scripts get a nil reply since none is run.
func redisEvalError(script []byte) redis.Reply {
	m := redisSandboxGlobals.Find(script)
	if m == nil {
		return redis.Nil()
	}
	sum := sha1.Sum(script)
	return redis.Error(fmt.Sprintf(
		"ERR Error running script (call to f_%x): @enable_strict_lua:15: user_script:1: Script attempted to access nonexistent global variable '%s' ",
		sum, m))
}

func redisHumanBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%dB", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.2fK", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.2fM", float64(n)/(1024*1024))
	}
	return fmt.Sprintf("%.2fG", float64(n)/(1024*1024*1024))
}

var redisInfoSections = []string{"server", "clients", "memory", "persistence", "stats", "replication", "cpu", "cluster", "keyspace"}

// info renders INFO for a section name, "default", "all" or "everything".
// An unknown section is an empty bulk, as on a real server.
func (s *redisServer) info(section string) string {
	var b strings.Builder
	for _, name := range redisInfoSections {
		if section != name && section != "default" && section != "all" && section != "everything" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\r\n")
		}
		title := strings.ToUpper(name[:1]) + name[1:]
		if name == "cpu" {
			title = "CPU"
		}
		b.WriteString("# " + title + "\r\n")
		for _, line := range s.infoSection(name) {
			b.WriteString(line + "\r\n")
		}
	}
	return b.String()
}

func (s *redisServer) infoSection(name string) []string {
	now := redisNow()
	uptime := int64(now.Sub(redisInstance.Started).Seconds())
	var data int64
	for k, v := range s.keys {
		data += int64(len(k) + len(v) + 64)
	}
	used := 857136 + data
	switch name {
	case "server":
		return []string{
			"redis_version:5.0.7", "redis_git_sha1:00000000", "redis_git_dirty:0",
			"redis_build_id:66bd629f924ac924", "redis_mode:standalone",
			"os:Linux 5.4.0-174-generic x86_64", "arch_bits:64", "multiplexing_api:epoll",
			"atomicvar_api:atomic-builtin", "gcc_version:9.3.0",
			fmt.Sprintf("process_id:%d", redisInstance.PID),
			"run_id:" + redisInstance.RunID,
			fmt.Sprintf("tcp_port:%d", s.port),
			fmt.Sprintf("uptime_in_seconds:%d", uptime),
			fmt.Sprintf("uptime_in_days:%d", uptime/86400),
			"hz:10", "configured_hz:10",
			fmt.Sprintf("lru_clock:%d", now.Unix()&(1<<24-1)),
			"executable:/usr/bin/redis-server", "config_file:/etc/redis/redis.conf",
		}
	case "clients":
		return []string{"connected_clients:1", "client_recent_max_input_buffer:2", "client_recent_max_output_buffer:0", "blocked_clients:0"}
	case "memory":
		return []string{
			fmt.Sprintf("used_memory:%d", used), "used_memory_human:" + redisHumanBytes(used),
			fmt.Sprintf("used_memory_rss:%d", used+2981888), "used_memory_rss_human:" + redisHumanBytes(used+2981888),
			fmt.Sprintf("used_memory_peak:%d", used+21360), "used_memory_peak_human:" + redisHumanBytes(used+21360),
			"total_system_memory:2084024320", "total_system_memory_human:1.94G",
			"maxmemory:0", "maxmemory_human:0B", "maxmemory_policy:" + s.config["maxmemory-policy"],
			"mem_fragmentation_ratio:4.48", "mem_allocator:jemalloc-5.2.1",
		}
	case "persistence":
		return []string{
			"loading:0", fmt.Sprintf("rdb_changes_since_last_save:%d", s.dirty),
			"rdb_bgsave_in_progress:0", fmt.Sprintf("rdb_last_save_time:%d", s.lastSave.Unix()),
			"rdb_last_bgsave_status:ok", "rdb_last_bgsave_time_sec:0", "rdb_current_bgsave_time_sec:-1",
			"aof_enabled:0", "aof_rewrite_in_progress:0", "aof_rewrite_scheduled:0",
			"aof_last_rewrite_time_sec:-1", "aof_current_rewrite_time_sec:-1",
			"aof_last_bgrewrite_status:ok", "aof_last_write_status:ok",
		}
	case "stats":
		return []string{
			fmt.Sprintf("total_connections_received:%d", s.clientID),
			fmt.Sprintf("total_commands_processed:%d", s.clientID*3+int64(s.commands)),
			"instantaneous_ops_per_sec:0", "rejected_connections:0", "expired_keys:0",
			"evicted_keys:0", "keyspace_hits:0", "keyspace_misses:0", "pubsub_channels:0",
		}
	case "replication":
		if s.master != "" {
			host, port, _ := net.SplitHostPort(s.master)
			return []string{
				"role:slave", "master_host:" + host, "master_port:" + port,
				"master_link_status:down", "master_last_io_seconds_ago:-1", "master_sync_in_progress:0",
				"slave_repl_offset:1", "slave_priority:100", "slave_read_only:1", "connected_slaves:0",
				"master_replid:" + redisInstance.ReplID, "master_repl_offset:0",
			}
		}
		return []string{"role:master", "connected_slaves:0", "master_replid:" + redisInstance.ReplID, "master_repl_offset:0"}
	case "cpu":
		return []string{
			fmt.Sprintf("used_cpu_sys:%.6f", float64(uptime)/2900),
			fmt.Sprintf("used_cpu_user:%.6f", float64(uptime)/3700),
			"used_cpu_sys_children:0.000000", "used_cpu_user_children:0.000000",
		}
	case "cluster":
		return []string{"cluster_enabled:0"}
	case "keyspace":
		if len(s.keys) == 0 {
			return nil
		}
		return []string{fmt.Sprintf("db0:keys=%d,expires=0,avg_ttl=0", len(s.keys))}
	}
	return nil
}
