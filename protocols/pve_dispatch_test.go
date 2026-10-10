package protocols

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/pve"
	"github.com/mushorg/glutton/rules"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type pveProduced struct {
	protocol string
	md       connection.Metadata
}

// pveHoneypot records the produced event's metadata, so tests can see the
// tls object the producer would emit.
type pveHoneypot struct {
	protocolHoneypot
	events chan pveProduced
}

func (h *pveHoneypot) ProduceTCP(protocol string, _ net.Conn, md connection.Metadata, _ []byte, _ interface{}) error {
	h.events <- pveProduced{protocol: protocol, md: md}
	return nil
}

// dispatchPVE serves one connection through the tcp/8006 rule (http, tls:
// auto) and returns the single produced event.
func dispatchPVE(t *testing.T, client func(net.Conn)) pveProduced {
	t.Helper()
	prev := viper.GetInt("conn_timeout")
	viper.Set("conn_timeout", 1) // HTTP sessions produce once idle this long
	t.Cleanup(func() { viper.Set("conn_timeout", prev) })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	hp := &pveHoneypot{events: make(chan pveProduced, 4)}
	handler := MapTCPProtocolHandlers(nopLogger{}, hp)["http"]
	require.NotNil(t, handler)

	md := connection.Metadata{TargetPort: pve.Port, Rule: &rules.Rule{Target: "http", TLS: rules.TLSAuto}}
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
	var ev pveProduced
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

func getIndex(t *testing.T, c io.ReadWriter) *http.Response {
	t.Helper()
	_, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: 127.0.0.1:8006\r\n\r\n")
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), pve.Node().Node+" - Proxmox Virtual Environment")
	return resp
}

func TestPVERuleTLS(t *testing.T) {
	ev := dispatchPVE(t, func(c net.Conn) {
		// the probe in Ochi event 511b7311-85e3-4126-8f11-63791c160838
		// was a TLS 1.3 hello with no SNI
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
		require.NoError(t, tc.Handshake())
		leaf := tc.ConnectionState().PeerCertificates[0]
		require.Equal(t, pve.Node().Node+"."+pve.Node().Domain, leaf.Subject.CommonName)
		require.Equal(t, "Proxmox Virtual Environment", leaf.Issuer.CommonName)
		require.Equal(t, []string{"PVE Cluster Manager CA"}, leaf.Issuer.Organization)

		resp := getIndex(t, tc)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "pve-api-daemon/3.0", resp.Header.Get("Server"))
	})
	require.Equal(t, "http", ev.protocol)
	require.NotNil(t, ev.md.TLS)
	require.Equal(t, "TLS 1.3", ev.md.TLS.Version)
	require.NotEmpty(t, ev.md.TLS.Cipher)
	require.NotEmpty(t, ev.md.TLS.Hello)
}

func TestPVERulePlaintext(t *testing.T) {
	ev := dispatchPVE(t, func(c net.Conn) {
		resp := getIndex(t, c)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
	require.Equal(t, "http", ev.protocol)
	require.Nil(t, ev.md.TLS)
}
