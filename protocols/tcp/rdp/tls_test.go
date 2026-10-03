package rdp

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestIsTLSRecord(t *testing.T) {
	require.True(t, IsTLSRecord([]byte{0x16, 0x03, 0x01, 0x00, 0x01}))
	require.True(t, IsTLSRecord([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46}))
	require.False(t, IsTLSRecord([]byte{0x03, 0x00, 0x00, 0x13}))
	require.False(t, IsTLSRecord([]byte{0x16, 0x02}))
	require.False(t, IsTLSRecord(nil))
}

func TestStubTLSHandshake(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	require.NoError(t, clientRaw.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, serverRaw.SetDeadline(time.Now().Add(5*time.Second)))

	var clientHello []byte
	errCh := make(chan error, 1)
	go func() {
		tlsClient := tls.Client(clientRaw, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
			ServerName:         "rdp",
			// Capture ClientHello by letting Handshake drive the pipe; server
			// side uses StubTLSHandshake which needs the first record prepended.
			// Instead: server reads first, then stubs — so client just Handshakes.
		})
		errCh <- tlsClient.Handshake()
	}()

	buf := make([]byte, 2048)
	n, err := serverRaw.Read(buf)
	require.NoError(t, err)
	clientHello = append([]byte(nil), buf[:n]...)
	require.True(t, IsTLSRecord(clientHello))

	written, err := StubTLSHandshake(serverRaw, clientHello)
	require.NoError(t, err)
	require.NotEmpty(t, written)
	require.Equal(t, byte(0x16), written[0], "stub should start with TLS Handshake record")

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("client handshake timed out")
	}
}
