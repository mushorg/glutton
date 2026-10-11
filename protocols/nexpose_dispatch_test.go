package protocols

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/rules"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// nexposePort is the Rapid7 Nexpose / InsightVM Security Console, HTTPS only.
const nexposePort = 3780

type httpsProduced struct {
	protocol string
	md       connection.Metadata
	decoded  []map[string]any
}

// httpsHoneypot records the produced event's metadata and decoded frames.
type httpsHoneypot struct {
	protocolHoneypot
	events chan httpsProduced
}

func (h *httpsHoneypot) ProduceTCP(protocol string, _ net.Conn, md connection.Metadata, _ []byte, decoded interface{}) error {
	ev := httpsProduced{protocol: protocol, md: md}
	raw, err := json.Marshal(decoded)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &ev.decoded); err != nil {
		return err
	}
	h.events <- ev
	return nil
}

// dispatchNexpose serves one connection through the tcp/3780 rule (http,
// tls: auto) and returns the single produced event.
func dispatchNexpose(t *testing.T, client func(net.Conn)) httpsProduced {
	t.Helper()
	prev := viper.GetInt("conn_timeout")
	viper.Set("conn_timeout", 1) // HTTP sessions produce once idle this long
	t.Cleanup(func() { viper.Set("conn_timeout", prev) })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	hp := &httpsHoneypot{events: make(chan httpsProduced, 4)}
	handler := MapTCPProtocolHandlers(nopLogger{}, hp)["http"]
	require.NotNil(t, handler)

	md := connection.Metadata{TargetPort: nexposePort, Rule: &rules.Rule{Target: "http", TLS: rules.TLSAuto}}
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- handler(context.Background(), conn, md)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	client(conn)
	require.NoError(t, conn.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	var ev httpsProduced
	select {
	case ev = <-hp.events:
	case <-time.After(5 * time.Second):
		t.Fatal("no event produced")
	}
	select {
	case extra := <-hp.events:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
	return ev
}

// TestNexposeRuleTLSNewline replays Ochi event
// e1ce739d-42d5-4666-a848-96b59c9d0847: a TLS 1.3 handshake, then a lone
// "\n" inside the tunnel. The catch-all answered it with random bytes; an
// HTTPS server skips the blank line and waits for a request line.
func TestNexposeRuleTLSNewline(t *testing.T) {
	ev := dispatchNexpose(t, func(c net.Conn) {
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "1.2.3.4"})
		require.NoError(t, tc.Handshake())
		_, err := tc.Write([]byte("\n"))
		require.NoError(t, err)

		require.NoError(t, tc.SetReadDeadline(time.Now().Add(300*time.Millisecond)))
		n, err := tc.Read(make([]byte, 1))
		require.Zero(t, n, "the server must not answer a blank line")
		require.True(t, errors.Is(err, os.ErrDeadlineExceeded), "got %v", err)
	})
	require.Equal(t, "http", ev.protocol)
	require.NotNil(t, ev.md.TLS)
	require.Equal(t, "TLS 1.3", ev.md.TLS.Version)
	require.Len(t, ev.decoded, 1)
	require.Equal(t, "read", ev.decoded[0]["direction"])
	require.Equal(t, "Cg==", ev.decoded[0]["payload"]) // "\n"
	for _, f := range ev.decoded {
		require.NotEqual(t, "random", f["status"])
	}
}

func TestNexposeRuleTLSRequest(t *testing.T) {
	ev := dispatchNexpose(t, func(c net.Conn) {
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
		require.NoError(t, tc.Handshake())
		_, err := io.WriteString(tc, "GET / HTTP/1.1\r\nHost: 127.0.0.1:3780\r\n\r\n")
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	})
	require.Equal(t, "http", ev.protocol)
	require.NotNil(t, ev.md.TLS)
	require.GreaterOrEqual(t, len(ev.decoded), 2)
	require.Equal(t, "read", ev.decoded[0]["direction"])
	require.Equal(t, "GET", ev.decoded[0]["command"])
	require.Equal(t, "write", ev.decoded[1]["direction"])
}
