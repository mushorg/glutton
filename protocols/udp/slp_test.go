package udp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// Captured infrawatch SrvRqst (Ochi event 79c746cf-1e02-4e46-baf8-b4c69438d318).
var slpCapturedSrvRqst = []byte{
	0x02, 0x01, 0x00, 0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xe8, 0x00, 0x02, 0x65, 0x6e,
	0x00, 0x00, 0x00, 0x2a, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x3a, 0x69, 0x77, 0x73, 0x63,
	0x61, 0x6e, 0x2d, 0x63, 0x36, 0x30, 0x64, 0x38, 0x35, 0x35, 0x32, 0x37, 0x35, 0x63, 0x31, 0x65,
	0x35, 0x31, 0x64, 0x2e, 0x69, 0x6e, 0x66, 0x72, 0x61, 0x77, 0x61, 0x74, 0x63, 0x68, 0x00, 0x17,
	0x69, 0x77, 0x73, 0x63, 0x61, 0x6e, 0x2d, 0x63, 0x36, 0x30, 0x64, 0x38, 0x35, 0x35, 0x32, 0x37,
	0x35, 0x63, 0x31, 0x65, 0x35, 0x31, 0x64, 0x00, 0x00, 0x00, 0x00,
}

var slpExpectedReply = []byte{
	0x02, 0x02, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xe8, 0x00, 0x02, 'e', 'n',
	0x00, 0x04, 0x00, 0x00,
}

func slpAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 57586},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 427}
}

func TestHandleSLPCapturedSrvRqst(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := slpAddrs()

	require.NoError(t, HandleSLP(context.Background(), src, dst, slpCapturedSrvRqst, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "slp", h.produced[0].handler)
	require.Equal(t, slpCapturedSrvRqst, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
	require.Equal(t, [][]byte{slpExpectedReply}, h.replies)
	require.Equal(t, []parsedSLP{
		{
			Direction:   "read",
			Command:     "SrvRqst",
			XID:         "0xc0e8",
			Lang:        "en",
			ServiceType: "service:iwscan-c60d855275c1e51d.infrawatch",
			Scope:       "iwscan-c60d855275c1e51d",
			Payload:     slpCapturedSrvRqst,
		},
		{Direction: "write", Command: "SrvRply", XID: "0xc0e8", Lang: "en", Status: "SCOPE_NOT_SUPPORTED", Payload: slpExpectedReply},
	}, h.produced[0].decoded)
}

func TestHandleSLPNoReplyForMulticast(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := slpAddrs()
	req := append([]byte(nil), slpCapturedSrvRqst...)
	req[5] = 0x20 // REQUEST MULTICAST
	require.NoError(t, HandleSLP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Len(t, h.produced, 1)
	require.Len(t, h.produced[0].decoded.([]parsedSLP), 1)
}

func TestHandleSLPRecordOnlyFunction(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := slpAddrs()
	req := append([]byte(nil), slpCapturedSrvRqst[:16]...)
	req[1] = 3 // SrvReg
	req[4] = 16
	require.NoError(t, HandleSLP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Equal(t, []parsedSLP{{Direction: "read", Command: "SrvReg", XID: "0xc0e8", Lang: "en", Payload: req}}, h.produced[0].decoded)
}

func TestHandleSLPMalformed(t *testing.T) {
	src, dst := slpAddrs()

	h := &recordingHoneypot{}
	short := slpCapturedSrvRqst[:8]
	require.NoError(t, HandleSLP(context.Background(), src, dst, short, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Equal(t, []parsedSLP{{Direction: "read", Command: "malformed", Payload: short, Truncated: true}}, h.produced[0].decoded)

	// readable header, datagram cut short of the length field
	h = &recordingHoneypot{}
	cut := slpCapturedSrvRqst[:60]
	require.NoError(t, HandleSLP(context.Background(), src, dst, cut, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Len(t, h.produced, 1)
	events := h.produced[0].decoded.([]parsedSLP)
	require.Equal(t, "SrvRqst", events[0].Command)
	require.True(t, events[0].Truncated)

	// valid length but a string length running past the end
	h = &recordingHoneypot{}
	bad := append([]byte(nil), slpCapturedSrvRqst...)
	bad[19] = 0xff
	require.NoError(t, HandleSLP(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Len(t, h.produced[0].decoded.([]parsedSLP), 1)
	require.True(t, h.produced[0].decoded.([]parsedSLP)[0].Truncated)
}

func TestHandleSLPCapsOversize(t *testing.T) {
	src, dst := slpAddrs()
	h := &recordingHoneypot{}
	big := make([]byte, 3000)
	copy(big, slpCapturedSrvRqst[:14])
	big[2], big[3], big[4] = 0, 0x0b, 0xb8 // length 3000
	big[13] = 0                            // empty language tag
	require.NoError(t, HandleSLP(context.Background(), src, dst, big, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedSLP)
	require.Len(t, events[0].Payload, maxSLPPayload)
	require.True(t, events[0].Truncated)
}

func TestHandleSLPReplyError(t *testing.T) {
	src, dst := slpAddrs()
	h := &failingReplyHoneypot{}
	require.NoError(t, HandleSLP(context.Background(), src, dst, slpCapturedSrvRqst, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndWriteError, h.produced[0].endReason)
}
