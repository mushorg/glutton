package udp

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/dtls"
	"github.com/stretchr/testify/require"
)

// Captured ClientHello (Ochi event bcbf3d9e-e2c6-4a69-abf8-fc015ead520a):
// DTLS 1.2 hello to udp/12246, empty cookie, one cipher suite, no extensions.
var dtlsCaptured = mustHex("16feff000000000000000000360100002a000000000000002afefd" +
	"000000007c77401e8ac822a0a018ff9308caac0a642fc92264bc08a816891930" +
	"0000" + "0002002f" + "0100")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func dtlsAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.30"), Port: 17789},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 12246}
}

func withDTLSSecret(t *testing.T) {
	t.Helper()
	prev := dtlsSecret
	dtlsSecret = []byte("test secret")
	t.Cleanup(func() { dtlsSecret = prev })
}

func TestHandleDTLSCaptured(t *testing.T) {
	withDTLSSecret(t)
	h := &recordingHoneypot{}
	src, dst := dtlsAddrs()

	require.NoError(t, HandleDTLS(context.Background(), src, dst, dtlsCaptured, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "dtls", h.produced[0].handler)
	require.Equal(t, dtlsCaptured, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	want := dtls.BuildHelloVerifyRequest(0, dtls.Cookie(dtlsSecret, src.IP, src.Port))
	require.Equal(t, [][]byte{want}, h.replies)
	require.Less(t, len(want), len(dtlsCaptured))
	require.Equal(t, []parsedDTLS{
		{Direction: "read", Command: "ClientHello", ClientVersion: "DTLS 1.2", CipherSuites: []uint16{0x002f}, Payload: dtlsCaptured},
		{Direction: "write", Command: "HelloVerifyRequest", Status: "ok", Payload: want},
	}, h.produced[0].decoded)
}

func TestHandleDTLSEchoesRecordSequence(t *testing.T) {
	withDTLSSecret(t)
	h := &recordingHoneypot{}
	src, dst := dtlsAddrs()
	hello := append([]byte(nil), dtlsCaptured...)
	hello[10] = 0x2a // record sequence 42

	require.NoError(t, HandleDTLS(context.Background(), src, dst, hello, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	require.Equal(t, hello[5:11], h.replies[0][5:11])
}

// The follow-up hello carries the cookie: it is recorded as valid and, as the
// handshake is not emulated, not answered. A wrong cookie gets a fresh HVR.
func TestHandleDTLSCookieHello(t *testing.T) {
	withDTLSSecret(t)
	src, dst := dtlsAddrs()
	cookie := dtls.Cookie(dtlsSecret, src.IP, src.Port)

	second := cookieHello(cookie)
	h := &recordingHoneypot{}
	require.NoError(t, HandleDTLS(context.Background(), src, dst, second, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedDTLS)
	require.Len(t, events, 1)
	require.Equal(t, "ClientHello", events[0].Command)
	require.True(t, events[0].CookiePresent)
	require.True(t, events[0].CookieValid)
	require.Equal(t, "ab", events[0].SessionID)
	require.Equal(t, "example.test", events[0].ServerName)
	require.Equal(t, []uint16{0}, events[0].Extensions)

	h = &recordingHoneypot{}
	other := &net.UDPAddr{IP: src.IP, Port: src.Port + 1}
	require.NoError(t, HandleDTLS(context.Background(), other, dst, second, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	events = h.produced[0].decoded.([]parsedDTLS)
	require.True(t, events[0].CookiePresent)
	require.False(t, events[0].CookieValid)
	require.Len(t, events, 2)
}

// cookieHello builds a DTLS 1.2 ClientHello with session ID 0xab, the cookie
// and an SNI extension for example.test.
func cookieHello(cookie []byte) []byte {
	name := "example.test"
	sni := append([]byte{0, byte(len(name) + 3), 0, 0, byte(len(name))}, name...)
	exts := append([]byte{0, 0, 0, byte(len(sni))}, sni...)
	body := append([]byte{0xfe, 0xfd}, make([]byte, 32)...)
	body = append(body, 1, 0xab, byte(len(cookie)))
	body = append(body, cookie...)
	body = append(body, 0, 2, 0x00, 0x2f, 1, 0, 0, byte(len(exts)))
	body = append(body, exts...)
	rec := append([]byte{1, 0, 0, byte(len(body)), 0, 1, 0, 0, 0, 0, 0, byte(len(body))}, body...)
	out := []byte{22, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 1, 0, byte(len(rec))}
	return append(out, rec...)
}

func TestHandleDTLSMalformed(t *testing.T) {
	withDTLSSecret(t)
	src, dst := dtlsAddrs()
	for _, n := range []int{0, 5, 13, 20, 40, 66} {
		h := &recordingHoneypot{}
		data := dtlsCaptured[:n]
		require.NoError(t, HandleDTLS(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h), "len %d", n)
		require.Len(t, h.produced, 1, "len %d", n)
		require.Empty(t, h.replies, "len %d", n)
		events := h.produced[0].decoded.([]parsedDTLS)
		require.Len(t, events, 1)
		require.Equal(t, "UNKNOWN", events[0].Command)
		require.Equal(t, data, events[0].Payload)
	}
}

func TestHandleDTLSCapsOversizedPayload(t *testing.T) {
	withDTLSSecret(t)
	h := &recordingHoneypot{}
	src, dst := dtlsAddrs()
	data := append(append([]byte(nil), dtlsCaptured...), make([]byte, 3000)...)

	require.NoError(t, HandleDTLS(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedDTLS)
	require.Len(t, events[0].Payload, maxDTLSPayload)
	require.True(t, events[0].Truncated)
	require.Equal(t, "ClientHello", events[0].Command) // trailing bytes do not matter
	require.Len(t, h.replies, 1)
}

type failingReplyHoneypot struct{ recordingHoneypot }

func (h *failingReplyHoneypot) ReplyUDP(*net.UDPAddr, *net.UDPAddr, []byte) error {
	return errors.New("boom")
}

func TestHandleDTLSReplyError(t *testing.T) {
	withDTLSSecret(t)
	h := &failingReplyHoneypot{}
	src, dst := dtlsAddrs()
	require.NoError(t, HandleDTLS(context.Background(), src, dst, dtlsCaptured, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndWriteError, h.produced[0].endReason)
}

func TestHandleUDPReroutesDTLS(t *testing.T) {
	t.Chdir(t.TempDir())
	withDTLSSecret(t)
	h := &recordingHoneypot{}
	src, dst := dtlsAddrs()

	require.NoError(t, HandleUDP(context.Background(), src, dst, dtlsCaptured, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "dtls", h.produced[0].handler)
	require.Len(t, h.replies, 1)
}

func TestHandleUDPKeepsNonDTLS(t *testing.T) {
	t.Chdir(t.TempDir())
	src, dst := dtlsAddrs()
	// Application-data record (type 23) and an epoch-1 handshake record are
	// not hellos the handler can answer; the catch-all keeps them.
	appData := append([]byte(nil), dtlsCaptured...)
	appData[0] = 23
	epoch1 := append([]byte(nil), dtlsCaptured...)
	epoch1[4] = 1
	for _, data := range [][]byte{appData, epoch1, dtlsCaptured[:30]} {
		h := &recordingHoneypot{}
		require.NoError(t, HandleUDP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
		require.Equal(t, "udp", h.produced[0].handler)
		require.Empty(t, h.replies)
	}
}
