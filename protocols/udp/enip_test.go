package udp

import (
	"context"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/enip"
	"github.com/stretchr/testify/require"
)

// Captured ListIdentity from Shodan (Ochi event 63ad2bfa-a05b-4d9d-86c2-a674891a46ce).
var enipCapturedListIdentity = []byte{
	0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x6a, 0x0e, 0xbe, 0x64, 0x00, 0x00, 0x00, 0x00,
}

func enipAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.20"), Port: 31515},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 44818}
}

func withENIPSerial(t *testing.T) {
	t.Helper()
	prev := enip.Serial
	enip.Serial = func() uint32 { return 0x11223344 }
	t.Cleanup(func() { enip.Serial = prev })
}

func TestHandleENIPListIdentity(t *testing.T) {
	withENIPSerial(t)
	h := &recordingHoneypot{}
	src, dst := enipAddrs()

	require.NoError(t, HandleENIP(context.Background(), src, dst, enipCapturedListIdentity, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "enip", h.produced[0].handler)
	require.Equal(t, enipCapturedListIdentity, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	id := enip.DefaultIdentity
	id.SerialNumber = 0x11223344
	req, err := enip.ParseHeader(enipCapturedListIdentity)
	require.NoError(t, err)
	wantWire := enip.ListIdentityReply(req, id, net.IPv4(198, 51, 100, 1), 44818)
	wantRecorded := enip.ListIdentityReply(req, id, net.IPv4(1, 2, 3, 4), 44818)
	require.Equal(t, [][]byte{wantWire}, h.replies)

	// the reply echoes the sender context and is a success ListIdentity
	got, err := enip.ParseHeader(h.replies[0])
	require.NoError(t, err)
	require.Equal(t, uint16(enip.CmdListIdentity), got.Command)
	require.Equal(t, req.SenderContext, got.SenderContext)
	require.Equal(t, uint32(enip.StatusSuccess), got.Status)
	require.Equal(t, len(h.replies[0])-enip.HeaderSize, int(got.Length))

	require.Equal(t, []parsedENIP{
		{Direction: "read", Command: "ListIdentity", SenderContext: "000000006a0ebe64", Payload: enipCapturedListIdentity},
		{Direction: "write", Command: "ListIdentity", SenderContext: "000000006a0ebe64", Status: "success", Payload: wantRecorded},
	}, h.produced[0].decoded)
}

func TestHandleENIPListServicesAndInterfaces(t *testing.T) {
	src, dst := enipAddrs()
	for name, cmd := range map[string]uint16{"ListServices": enip.CmdListServices, "ListInterfaces": enip.CmdListInterfaces} {
		h := &recordingHoneypot{}
		req := enip.Header{Command: cmd}.Marshal(nil)
		require.NoError(t, HandleENIP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
		require.Len(t, h.replies, 1, name)
		events := h.produced[0].decoded.([]parsedENIP)
		require.Len(t, events, 2, name)
		require.Equal(t, name, events[1].Command)
		require.Equal(t, "success", events[1].Status)
		require.Equal(t, h.replies[0], events[1].Payload)
	}
}

func TestHandleENIPNoReplyForOtherCommands(t *testing.T) {
	src, dst := enipAddrs()
	h := &recordingHoneypot{}
	req := enip.Header{Command: enip.CmdRegisterSession}.Marshal([]byte{1, 0, 0, 0})
	require.NoError(t, HandleENIP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Len(t, h.produced, 1)
	events := h.produced[0].decoded.([]parsedENIP)
	require.Len(t, events, 1)
	require.Equal(t, "RegisterSession", events[0].Command)
}

func TestHandleENIPMalformed(t *testing.T) {
	src, dst := enipAddrs()
	h := &recordingHoneypot{}
	short := enipCapturedListIdentity[:10]
	require.NoError(t, HandleENIP(context.Background(), src, dst, short, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Len(t, h.produced, 1)
	require.Equal(t, []parsedENIP{{Direction: "read", Command: "malformed", Payload: short, Truncated: true}}, h.produced[0].decoded)
}

func TestHandleENIPCapsOversize(t *testing.T) {
	src, dst := enipAddrs()
	h := &recordingHoneypot{}
	body := make([]byte, 3000)
	req := enip.Header{Command: enip.CmdNOP}.Marshal(body)
	require.NoError(t, HandleENIP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedENIP)
	require.Len(t, events[0].Payload, maxENIPPayload)
	require.True(t, events[0].Truncated)
}

func TestHandleENIPReplyError(t *testing.T) {
	src, dst := enipAddrs()
	h := &failingReplyHoneypot{}
	require.NoError(t, HandleENIP(context.Background(), src, dst, enipCapturedListIdentity, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndWriteError, h.produced[0].endReason)
}

func TestHandleUDPPeeksENIP(t *testing.T) {
	withENIPSerial(t)
	origPick := pickDispatch
	t.Cleanup(func() { pickDispatch = origPick })
	pickDispatch = func(int) int { t.Fatal("ListIdentity must match only enip"); return 0 }

	src, dst := enipAddrs()
	dst.Port = 2222 // any port reaches enip through the catch-all
	h := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, enipCapturedListIdentity, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "enip", h.produced[0].handler)
	require.Len(t, h.replies, 1)
}

func TestHandleUDPDoesNotPeekENIPOnOtherData(t *testing.T) {
	t.Chdir(t.TempDir())
	src, dst := enipAddrs()
	h := &recordingHoneypot{}
	// ListIdentity header whose length field claims a body that is not there
	bad := append([]byte(nil), enipCapturedListIdentity...)
	bad[2] = 9
	require.NoError(t, HandleUDP(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "udp", h.produced[0].handler)
	require.Empty(t, h.replies)
}
