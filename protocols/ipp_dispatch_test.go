package protocols

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/rules"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// dispatchIPP serves one connection through the tcp/631 rule (ipp,
// tls: auto) and returns the single produced event.
func dispatchIPP(t *testing.T, client func(net.Conn)) httpsProduced {
	t.Helper()
	prev := viper.GetInt("conn_timeout")
	viper.Set("conn_timeout", 2)
	t.Cleanup(func() { viper.Set("conn_timeout", prev) })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	hp := &httpsHoneypot{events: make(chan httpsProduced, 4)}
	handler := MapTCPProtocolHandlers(nopLogger{}, hp)["ipp"]
	require.NotNil(t, handler)

	md := connection.Metadata{TargetPort: 631, Rule: &rules.Rule{Target: "ipp", TLS: rules.TLSAuto}}
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
	require.NoError(t, conn.SetDeadline(time.Now().Add(8*time.Second)))
	client(conn)
	require.NoError(t, conn.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(8 * time.Second):
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

// TestIPPRuleLateClientHello replays the Censys tcp/631 sessions of
// 2026-11-08 (66.132.224.82): the scanner waits ~5s for a banner before its
// ClientHello, past the tls: auto sniff window, so the catch-all answered the
// handshake and produced a "tcp" event without a tls object. The late
// ClientHello is now terminated and the decrypted request reaches IPP.
func TestIPPRuleLateClientHello(t *testing.T) {
	ev := dispatchIPP(t, func(c net.Conn) {
		time.Sleep(tlsAutoWait + 200*time.Millisecond)
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "cups.example"})
		require.NoError(t, tc.Handshake())
		_, err := tc.Write([]byte("GET / HTTP/1.1\r\nHost: 1.2.3.4:631\r\nConnection: close\r\n\r\n"))
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	})
	require.Equal(t, "ipp", ev.protocol)
	require.NotNil(t, ev.md.TLS)
	require.Equal(t, "cups.example", ev.md.TLS.ServerName)
	require.Contains(t, ev.md.Outer, "tls")
	require.NotEmpty(t, ev.decoded)
	require.Equal(t, "read", ev.decoded[0]["direction"])
}

// TestIPPRuleLateClientHelloOnly covers the observed session shape: a
// handshake and then a close, with no request inside the tunnel. It still
// produces one ipp event that carries the ClientHello metadata.
func TestIPPRuleLateClientHelloOnly(t *testing.T) {
	ev := dispatchIPP(t, func(c net.Conn) {
		time.Sleep(tlsAutoWait + 200*time.Millisecond)
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "cups.example"})
		require.NoError(t, tc.Handshake())
	})
	require.Equal(t, "ipp", ev.protocol)
	require.NotNil(t, ev.md.TLS)
	require.Equal(t, "cups.example", ev.md.TLS.ServerName)
	require.NotEmpty(t, ev.md.TLS.JA4)
}

// TestIPPRuleLatePlainHTTP keeps a slow plaintext request on IPP untouched.
func TestIPPRuleLatePlainHTTP(t *testing.T) {
	ev := dispatchIPP(t, func(c net.Conn) {
		time.Sleep(tlsAutoWait + 200*time.Millisecond)
		_, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: 1.2.3.4:631\r\nConnection: close\r\n\r\n"))
		require.NoError(t, err)
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
	})
	require.Equal(t, "ipp", ev.protocol)
	require.Nil(t, ev.md.TLS)
}
