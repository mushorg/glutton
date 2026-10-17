package udp

import (
	"context"
	"crypto/md5" //nolint:gosec
	"encoding/hex"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// Captured infrawatch Access-Request (Ochi event 48449bf5-270b-4ba6-a200-480ca094afb4).
var radiusCapturedAccessRequest = []byte{
	0x01, 0xbc, 0x00, 0x50, 0x2a, 0xf2, 0xd1, 0x31, 0x64, 0x51, 0x20, 0x8b, 0x93, 0xee, 0xdb, 0x85,
	0x37, 0x86, 0xba, 0x26, 0x01, 0x3c, 0x69, 0x6e, 0x66, 0x72, 0x61, 0x67, 0x72, 0x61, 0x62, 0x2d,
	0x32, 0x61, 0x66, 0x32, 0x64, 0x31, 0x33, 0x31, 0x36, 0x34, 0x35, 0x31, 0x32, 0x30, 0x38, 0x62,
	0x39, 0x33, 0x65, 0x65, 0x64, 0x62, 0x38, 0x35, 0x33, 0x37, 0x38, 0x36, 0x62, 0x61, 0x32, 0x36,
	0x40, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x2e, 0x69, 0x6e, 0x76, 0x61, 0x6c, 0x69, 0x64,
}

func radiusAddrs(port int) (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 41555},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: port}
}

// radiusExpectedReply computes the Response Authenticator the handler uses
// (MD5 over the reply header, request authenticator and the reply secret).
func radiusExpectedReply(code, id byte, reqAuth []byte) []byte {
	resp := append([]byte{code, id, 0x00, 0x14}, reqAuth...)
	sum := md5.Sum(append(append([]byte(nil), resp...), "radius"...)) //nolint:gosec
	return append(resp[:4:4], sum[:]...)
}

func TestHandleRADIUSCapturedAccessRequest(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := radiusAddrs(1812)

	require.NoError(t, HandleRADIUS(context.Background(), src, dst, radiusCapturedAccessRequest, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "radius", h.produced[0].handler)
	require.Equal(t, radiusCapturedAccessRequest, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	reply := radiusExpectedReply(3, 0xbc, radiusCapturedAccessRequest[4:20])
	require.Equal(t, [][]byte{reply}, h.replies)
	require.Less(t, len(reply), len(radiusCapturedAccessRequest))
	require.Equal(t, []parsedRADIUS{
		{
			Direction:  "read",
			Command:    "Access-Request",
			Identifier: 0xbc,
			Username:   "infragrab-2af2d1316451208b93eedb853786ba26@invalid.invalid",
			Payload:    radiusCapturedAccessRequest,
		},
		{Direction: "write", Command: "Access-Reject", Identifier: 0xbc, Status: "reject", Payload: reply},
	}, h.produced[0].decoded)
}

func radiusHide(secret, password string, auth []byte) []byte {
	pw := append([]byte(password), make([]byte, 16-len(password))...)
	sum := md5.Sum(append([]byte(secret), auth...)) //nolint:gosec
	out := make([]byte, 16)
	for i := range out {
		out[i] = pw[i] ^ sum[i]
	}
	return out
}

func radiusPacket(code, id byte, auth []byte, attrs ...[]byte) []byte {
	body := []byte{}
	for _, a := range attrs {
		body = append(body, a...)
	}
	n := 20 + len(body)
	return append(append([]byte{code, id, byte(n >> 8), byte(n)}, auth...), body...)
}

func radiusAttr(t byte, v []byte) []byte { return append([]byte{t, byte(len(v) + 2)}, v...) }

func TestHandleRADIUSCredentialsAndNAS(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := radiusAddrs(1812)
	auth := []byte("0123456789abcdef")
	hidden := radiusHide("testing123", "hunter2", auth)
	req := radiusPacket(1, 7, auth,
		radiusAttr(1, []byte("admin")),
		radiusAttr(2, hidden),
		radiusAttr(4, []byte{10, 0, 0, 5}),
		radiusAttr(32, []byte("nas01")),
		radiusAttr(31, []byte("00-11-22-33-44-55")),
		radiusAttr(30, []byte("aa-bb-cc-dd-ee-ff")),
		radiusAttr(80, make([]byte, 16)),
	)

	require.NoError(t, HandleRADIUS(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedRADIUS)
	require.Len(t, events, 2)
	require.Equal(t, parsedRADIUS{
		Direction:            "read",
		Command:              "Access-Request",
		Identifier:           7,
		Username:             "admin",
		Password:             "hunter2",
		PasswordHidden:       hex.EncodeToString(hidden),
		NASIP:                "10.0.0.5",
		NASIdentifier:        "nas01",
		CallingStationID:     "00-11-22-33-44-55",
		CalledStationID:      "aa-bb-cc-dd-ee-ff",
		MessageAuthenticator: true,
		Payload:              req,
	}, events[0])
}

func TestHandleRADIUSUnknownSecretKeepsHiddenPassword(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := radiusAddrs(1812)
	auth := []byte("0123456789abcdef")
	hidden := radiusHide("not-a-common-secret", "hunter2", auth)
	req := radiusPacket(1, 1, auth, radiusAttr(1, []byte("root")), radiusAttr(2, hidden))

	require.NoError(t, HandleRADIUS(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	first := h.produced[0].decoded.([]parsedRADIUS)[0]
	require.Empty(t, first.Password)
	require.Equal(t, hex.EncodeToString(hidden), first.PasswordHidden)
}

func TestHandleRADIUSAccounting(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := radiusAddrs(1813)
	auth := []byte("fedcba9876543210")
	req := radiusPacket(4, 9, auth, radiusAttr(1, []byte("bob")), radiusAttr(40, []byte{0, 0, 0, 1}))

	require.NoError(t, HandleRADIUS(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	reply := radiusExpectedReply(5, 9, auth)
	require.Equal(t, [][]byte{reply}, h.replies)
	require.Equal(t, []parsedRADIUS{
		{Direction: "read", Command: "Accounting-Request", Identifier: 9, Username: "bob", Payload: req},
		{Direction: "write", Command: "Accounting-Response", Identifier: 9, Status: "ok", Payload: reply},
	}, h.produced[0].decoded)
}

func TestHandleRADIUSStatusServer(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := radiusAddrs(1812)
	req := radiusPacket(12, 3, []byte("0123456789abcdef"), radiusAttr(80, make([]byte, 16)))
	require.NoError(t, HandleRADIUS(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	require.Equal(t, byte(2), h.replies[0][0])
}

func TestHandleRADIUSRecordOnlyCode(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := radiusAddrs(1812)
	req := radiusPacket(2, 4, make([]byte, 16))
	require.NoError(t, HandleRADIUS(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Equal(t, []parsedRADIUS{{Direction: "read", Command: "Access-Accept", Identifier: 4, Payload: req}}, h.produced[0].decoded)
}

func TestHandleRADIUSMalformed(t *testing.T) {
	src, dst := radiusAddrs(1812)

	h := &recordingHoneypot{}
	short := radiusCapturedAccessRequest[:8]
	require.NoError(t, HandleRADIUS(context.Background(), src, dst, short, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Equal(t, []parsedRADIUS{{Direction: "read", Command: "malformed", Payload: short, Truncated: true}}, h.produced[0].decoded)

	// length field longer than the datagram (truncated)
	h = &recordingHoneypot{}
	cut := radiusCapturedAccessRequest[:60]
	require.NoError(t, HandleRADIUS(context.Background(), src, dst, cut, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Len(t, h.produced, 1)
	events := h.produced[0].decoded.([]parsedRADIUS)
	require.Len(t, events, 1)
	require.Equal(t, "Access-Request", events[0].Command)
	require.True(t, events[0].Truncated)

	// attribute length running past the packet: username already parsed is not lost
	h = &recordingHoneypot{}
	bad := radiusPacket(1, 1, make([]byte, 16), radiusAttr(1, []byte("ok")), []byte{5, 0xff, 0})
	require.NoError(t, HandleRADIUS(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events = h.produced[0].decoded.([]parsedRADIUS)
	require.Len(t, events, 1)
	require.Equal(t, "ok", events[0].Username)
	require.True(t, events[0].Truncated)
}

func TestHandleRADIUSCapsOversize(t *testing.T) {
	src, dst := radiusAddrs(1812)
	h := &recordingHoneypot{}
	big := make([]byte, 6000)
	copy(big, radiusCapturedAccessRequest)
	require.NoError(t, HandleRADIUS(context.Background(), src, dst, big, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Len(t, h.produced[0].payload, maxRADIUSPayload)
	require.True(t, h.produced[0].decoded.([]parsedRADIUS)[0].Truncated)
}
