package protocols

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/spicy"
	"github.com/mushorg/glutton/protocols/tcp/banners"
	"github.com/mushorg/glutton/protocols/tcp/firebird"
	"github.com/mushorg/glutton/protocols/tcp/mssql"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestCatchAllSendsBannerWithoutClientData(t *testing.T) {
	t.Chdir(t.TempDir())
	prev := viper.GetInt("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	t.Cleanup(func() { viper.Set("max_tcp_payload", prev) })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	hp := &protocolHoneypot{produced: make(chan string, 4)}
	handler := MapTCPProtocolHandlers(nopLogger{}, hp)["tcp"]
	require.NotNil(t, handler)

	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- handler(context.Background(), conn, connection.Metadata{TargetPort: 22})
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	// well under the 2s idle deadline: the banner must not wait for client bytes
	require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
	line, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", line)
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish")
	}
	require.Equal(t, "tcp", <-hp.produced)
}

// startCatchAllDispatch serves one connection on port through the catch-all
// dispatcher with a short greet wait.
func startCatchAllDispatch(t *testing.T, port uint16) (net.Conn, *protocolHoneypot, chan error) {
	t.Helper()
	t.Chdir(t.TempDir())
	prevMax := viper.GetInt("max_tcp_payload")
	viper.Set("max_tcp_payload", 4096)
	prevWait := greetWait
	greetWait = 100 * time.Millisecond
	t.Cleanup(func() {
		viper.Set("max_tcp_payload", prevMax)
		greetWait = prevWait
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })

	hp := &protocolHoneypot{produced: make(chan string, 4)}
	handler := MapTCPProtocolHandlers(nopLogger{}, hp)["tcp"]
	require.NotNil(t, handler)

	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- handler(context.Background(), conn, connection.Metadata{TargetPort: port})
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func finishCatchAllDispatch(t *testing.T, client net.Conn, hp *protocolHoneypot, done chan error) string {
	t.Helper()
	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not finish")
	}
	select {
	case protocol := <-hp.produced:
		return protocol
	case <-time.After(time.Second):
		t.Fatal("no event produced")
	}
	return ""
}

func TestCatchAllGreetsSilentClientOnIdlePort(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 4444)

	want, _ := banners.ForPort(4444)
	got := make([]byte, len(want.Data))
	_, err := io.ReadFull(client, got)
	require.NoError(t, err)
	require.Equal(t, want.Data, got)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllIdlePortClientFirstNotGreeted(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 4444)

	_, err := client.Write([]byte("whoami\r\n"))
	require.NoError(t, err)
	// one prompt as the reply, no greeting before it
	want, _ := banners.ForPort(4444)
	reply := make([]byte, len(want.Data))
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	require.Equal(t, want.Data, reply)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func enableSpicy(t *testing.T) {
	t.Helper()
	if err := spicy.Initialize(nopLogger{}); err != nil {
		t.Skipf("Skipping test as Spicy initialization failed: %v", err)
	}
	prev := viper.GetBool("spicy.enabled")
	viper.Set("spicy.enabled", true)
	t.Cleanup(func() { viper.Set("spicy.enabled", prev) })
}

func TestCatchAllIdlePortRoutesHTTP(t *testing.T) {
	enableSpicy(t)
	client, hp, done := startCatchAllDispatch(t, 4444)

	// shorter than the 96-byte MCP peek: the request must not be lost
	_, err := client.Write([]byte("GET /wd/hub/status HTTP/1.1\r\nHost: 192.0.2.1:4444\r\n\r\n"))
	require.NoError(t, err)
	line, err := bufio.NewReader(client).ReadString('\n')
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(line, "HTTP/1.1 "), "%q", line)

	require.Equal(t, "http", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllShortPayloadWithSpicy(t *testing.T) {
	enableSpicy(t)
	client, hp, done := startCatchAllDispatch(t, 4444)

	// shorter than the 16-byte protocol peek: still handled, not dropped
	_, err := client.Write([]byte("whoami\r\n"))
	require.NoError(t, err)
	want, _ := banners.ForPort(4444)
	reply := make([]byte, len(want.Data))
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	require.Equal(t, want.Data, reply)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllLongPayloadWithSpicy(t *testing.T) {
	enableSpicy(t)
	client, hp, done := startCatchAllDispatch(t, 9999)

	// past the 16-byte protocol peek: the bytes must reach HandleTCP, which
	// answers with random bytes
	_, err := client.Write([]byte("\x10\x20\x30\x40 not a known protocol at all\r\n"))
	require.NoError(t, err)
	// the catch-all waits for a next message: read just the reply
	reply := make([]byte, 4096)
	n, err := client.Read(reply)
	require.NoError(t, err)
	require.NotZero(t, n)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllRoutesSOCKS(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 5678)

	// SOCKS4a CONNECT httpbin.org:80 from Ochi event
	// 2e27fe0b-5593-4090-bc5b-fddebc9666c6
	_, err := client.Write([]byte("\x04\x01\x00\x50\x00\x00\x00\x01\x00httpbin.org\x00"))
	require.NoError(t, err)
	reply := make([]byte, 8)
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x5a}, reply[:2])

	require.Equal(t, "socks", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllRoutesSOCKS5Greeting(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 9999)

	_, err := client.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	reply := make([]byte, 2)
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0x00}, reply)

	require.Equal(t, "socks", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllSOCKSLookalikeStaysTCP(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 9999)

	// SOCKS4 header without the userid terminator: not SOCKS, keep all bytes
	_, err := client.Write([]byte("\x04\x01\x00\x50\x01\x02\x03\x04not a socks request"))
	require.NoError(t, err)
	// the catch-all waits for a next message: read just the reply
	reply := make([]byte, 4096)
	n, err := client.Read(reply)
	require.NoError(t, err)
	require.NotZero(t, n)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllRoutesOffPortRDP(t *testing.T) {
	// no Spicy: RDP routing must not depend on it
	client, hp, done := startCatchAllDispatch(t, 49119)

	// RDP CR with cookie mstshash=Administr from Ochi event
	// 325c8103-b64a-4aeb-a2a3-3a8c9c32e05c (TPKT length 47, not 43)
	cr := append([]byte{0x03, 0x00, 0x00, 0x2f, 0x2a, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00},
		"Cookie: mstshash=Administr\r\n"...)
	cr = append(cr, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00)
	_, err := client.Write(cr)
	require.NoError(t, err)
	reply := make([]byte, 19)
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	// Connection Confirm with RDP_NEG_RSP
	require.Equal(t, []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0}, reply[:6])
	require.Equal(t, byte(0x02), reply[11])

	require.Equal(t, "rdp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllTPKTLookalikeStaysTCP(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 9999)

	// TPKT-framed X.224 Data TPDU, not a Connection Request
	_, err := client.Write([]byte{0x03, 0x00, 0x00, 0x0c, 0x02, 0xf0, 0x80, 0x7f, 0x65, 0x82, 0x00, 0x00})
	require.NoError(t, err)
	// the catch-all waits for a next message: read just the reply
	reply := make([]byte, 4096)
	n, err := client.Read(reply)
	require.NoError(t, err)
	require.NotZero(t, n)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllShortTPKTPrefixStaysTCP(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 9999)

	// shorter than the RDP peek: still handled, not dropped
	_, err := client.Write([]byte{0x03, 0x00, 0x00, 0x2f})
	require.NoError(t, err)
	// the catch-all waits for a next message: read just the reply
	reply := make([]byte, 4096)
	n, err := client.Read(reply)
	require.NoError(t, err)
	require.NotZero(t, n)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllRoutesOffPortMSSQL(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 14330)

	// Nmap PRELOGIN from Ochi event 024dea0c-f1a6-418f-b1a0-c2f50b093e1e
	prelogin := []byte{
		0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
		0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03, 0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,
		0x55, 0x00, 0x00, 0x02, 0x4d, 0x53, 0x53, 0x51, 0x4c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x00,
		0x00, 0x00, 0x31, 0x32,
	}
	_, err := client.Write(prelogin)
	require.NoError(t, err)
	want := mssql.BuildPreloginResponse()
	reply := make([]byte, len(want))
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	require.Equal(t, want, reply)

	require.Equal(t, "mssql", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllPreloginLookalikeStaysTCP(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 9999)

	// type 0x12 but not a final packet starting with the VERSION option
	_, err := client.Write([]byte{0x12, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	require.NoError(t, err)
	// the catch-all waits for a next message: read just the reply
	reply := make([]byte, 4096)
	n, err := client.Read(reply)
	require.NoError(t, err)
	require.NotZero(t, n)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllRoutesOffPortFirebird(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 13050)

	// nmap op_connect from Ochi event e0fc5f6b-f5e3-4d4f-b68d-e2366279125c
	probe := []byte("\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x02\x00\x00\x00$\x00\x00\x00\x0bservice_mgr\x00\x00\x00\x00\x02\x00\x00\x00\x13\x01\x08scanner \x04\x05nmap \x06\x00\x00\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\n\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04")
	_, err := client.Write(probe)
	require.NoError(t, err)
	want := firebird.BuildAccept(firebird.Protocol{Version: firebird.ProtocolVersion10, Arch: firebird.ArchGeneric, MaxType: 3})
	reply := make([]byte, len(want))
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	require.Equal(t, want, reply)

	require.Equal(t, "firebird", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllConnectLookalikeStaysTCP(t *testing.T) {
	client, hp, done := startCatchAllDispatch(t, 9999)

	// opcode 1 but an operation that is not an attach
	_, err := client.Write([]byte{0, 0, 0, 1, 0, 0, 0, 0x42, 0, 0, 0, 2, 0, 0, 0, 0x24})
	require.NoError(t, err)
	reply := make([]byte, 4096)
	n, err := client.Read(reply)
	require.NoError(t, err)
	require.NotZero(t, n)

	require.Equal(t, "tcp", finishCatchAllDispatch(t, client, hp, done))
}

func TestCatchAllPicksAmongMatchingProtocols(t *testing.T) {
	origMatchers, origPick := catchAllMatchers, pickDispatch
	t.Cleanup(func() { catchAllMatchers, pickDispatch = origMatchers, origPick })

	var handled []string
	stub := func(name string, need int, matches bool) catchAllMatcher {
		return catchAllMatcher{
			name:  name,
			peek:  fixedPeek(need, func([]byte) bool { return true }),
			match: func(b []byte) bool { return matches && string(b) == "ABCDEFGH" },
			handle: func(_ context.Context, conn BufferedConn, _ connection.Metadata, _ interfaces.Logger, _ interfaces.Honeypot) error {
				handled = append(handled, name)
				return conn.Close()
			},
		}
	}
	// the longest peek covers every gated matcher before any match runs
	catchAllMatchers = []catchAllMatcher{stub("a", 4, true), stub("b", 8, false), stub("c", 8, true)}

	var choices []int
	pickDispatch = func(n int) int {
		choices = append(choices, n)
		return n - 1
	}
	names := dispatchTarget(t, "tcp", 7001, func(c net.Conn) {
		_, err := c.Write([]byte("ABCDEFGH"))
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 1))
	})
	require.Empty(t, names)
	require.Equal(t, []int{2}, choices)
	require.Equal(t, []string{"c"}, handled)
}
