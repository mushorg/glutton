package udp

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/snmp"
	"github.com/stretchr/testify/require"
)

// Captured GetBulk from 151.243.11.230
// (Ochi event 7046da12-95f6-463e-8b55-8df479078229).
var snmpGetBulk = []byte{
	0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa5, 0x18, 0x02,
	0x04, 0x9e, 0xf9, 0x98, 0xb4, 0x02, 0x01, 0x00, 0x02, 0x02, 0x07, 0xd0, 0x30, 0x09, 0x30, 0x07,
	0x06, 0x03, 0x2b, 0x06, 0x01, 0x05, 0x00,
}

// snmpGetSysDescr is an SNMPv1 GET of sysDescr.0 with community public.
var snmpGetSysDescr = []byte{
	0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
	0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
	0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
}

func snmpAddrs() (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("151.243.11.230"), Port: 33616},
		&net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 161}
}

func swapSNMPAgent(t *testing.T) {
	t.Helper()
	old := snmpAgent
	snmpAgent = snmp.NewAgent(1, func() time.Time { return time.Unix(1_700_000_000, 0) })
	t.Cleanup(func() { snmpAgent = old })
}

func TestHandleSNMPGetBulk(t *testing.T) {
	swapSNMPAgent(t)
	h := &recordingHoneypot{}
	src, dst := snmpAddrs()

	require.NoError(t, HandleSNMP(context.Background(), src, dst, snmpGetBulk, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "snmp", h.produced[0].handler)
	require.Equal(t, snmpGetBulk, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	// 39 bytes cannot hold a sysDescr binding: the reply is tooBig and no
	// larger than the request.
	require.Len(t, h.replies, 1)
	require.LessOrEqual(t, len(h.replies[0]), len(snmpGetBulk))
	require.Equal(t, []parsedSNMP{
		{
			Direction: "read", Command: "GetBulkRequest", Version: "v2c", Community: "public",
			RequestID: -1627809612, MaxRepetitions: 2000, OIDs: []string{"1.3.6.1"}, Payload: snmpGetBulk,
		},
		{Direction: "write", Command: "GetResponse", Status: snmp.StatusTooBig, Payload: h.replies[0]},
	}, h.produced[0].decoded)
}

func TestHandleSNMPGetV1(t *testing.T) {
	swapSNMPAgent(t)
	h := &recordingHoneypot{}
	src, dst := snmpAddrs()
	// The sysDescr value is longer than the 40-byte request, so it is tooBig.
	req := snmpGetSysDescr
	require.NoError(t, HandleSNMP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))

	events := h.produced[0].decoded.([]parsedSNMP)
	require.Len(t, events, 2)
	require.Equal(t, "GetRequest", events[0].Command)
	require.Equal(t, "v1", events[0].Version)
	require.Equal(t, int64(42), events[0].RequestID)
	require.Equal(t, []string{"1.3.6.1.2.1.1.1.0"}, events[0].OIDs)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, snmp.StatusTooBig, events[1].Status)
	require.LessOrEqual(t, len(h.replies[0]), len(req))
}

func TestHandleSNMPUnknownCommunityIsSilent(t *testing.T) {
	swapSNMPAgent(t)
	h := &recordingHoneypot{}
	src, dst := snmpAddrs()
	req := append([]byte(nil), snmpGetBulk...)
	copy(req[7:13], "secret")

	require.NoError(t, HandleSNMP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedSNMP)
	require.Len(t, events, 1)
	require.Equal(t, "secret", events[0].Community)
}

// snmpV3Discovery is the SNMPv3 engine-discovery GetRequest for sysObjectID
// from 64.205.72.85 (Ochi event da656960-b52d-4f05-a47f-da632ad36e57).
var snmpV3Discovery = []byte{
	0x30, 0x4b, 0x02, 0x01, 0x03, 0x30, 0x10, 0x02, 0x04, 0x44, 0xba, 0x33, 0x55, 0x02, 0x02, 0x10,
	0x00, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00,
	0x02, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x22, 0x04, 0x00, 0x04, 0x00, 0xa0,
	0x1c, 0x02, 0x04, 0x4a, 0x85, 0x17, 0xe1, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
	0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00, 0x05, 0x00,
}

func berTLV(tag byte, content ...[]byte) []byte {
	var body []byte
	for _, c := range content {
		body = append(body, c...)
	}
	return append([]byte{tag, byte(len(body))}, body...)
}

// snmpV3Probe is a noAuthNoPriv reportable GetRequest for sysDescr from user
// with a learned engineID.
func snmpV3Probe(engineID []byte, user string) []byte {
	i := func(v byte) []byte { return berTLV(0x02, []byte{v}) }
	usm := berTLV(0x30, berTLV(0x04, engineID), i(1), i(1), berTLV(0x04, []byte(user)), berTLV(0x04), berTLV(0x04))
	vb := berTLV(0x30, berTLV(0x30, berTLV(0x06, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}), []byte{0x05, 0x00}))
	pdu := berTLV(0xa0, i(7), i(0), i(0), vb)
	return berTLV(0x30, i(3),
		berTLV(0x30, i(9), berTLV(0x02, []byte{0x10, 0x00}), berTLV(0x04, []byte{0x04}), i(3)),
		berTLV(0x04, usm),
		berTLV(0x30, berTLV(0x04, engineID), berTLV(0x04), pdu))
}

func TestHandleSNMPv3Discovery(t *testing.T) {
	swapSNMPAgent(t)
	h := &recordingHoneypot{}
	src, dst := snmpAddrs()

	require.NoError(t, HandleSNMP(context.Background(), src, dst, snmpV3Discovery, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, snmpV3Discovery, h.produced[0].payload)
	require.Len(t, h.replies, 1)
	// A Report is larger than the probe but capped.
	require.LessOrEqual(t, len(h.replies[0]), 160)
	require.Equal(t, []parsedSNMP{
		{
			Direction: "read", Command: "GetRequest", Version: "v3", RequestID: 0x4a8517e1,
			OIDs: []string{"1.3.6.1.2.1.1.2.0"}, MsgID: 0x44ba3355, MsgFlags: 4, Payload: snmpV3Discovery,
		},
		{Direction: "write", Command: "Report", Status: snmp.StatusUnknownEngineID, Payload: h.replies[0]},
	}, h.produced[0].decoded)
}

func TestHandleSNMPv3SecondProbeRecordsUser(t *testing.T) {
	swapSNMPAgent(t)
	src, dst := snmpAddrs()
	// Learn the engineID from the first Report, then guess a user with it.
	h := &recordingHoneypot{}
	require.NoError(t, HandleSNMP(context.Background(), src, dst, snmpV3Discovery, connection.Metadata{}, testLogger{}, h))
	report, err := snmp.Parse(h.replies[0])
	require.NoError(t, err)
	require.Equal(t, snmp.PDUReport, int(report.PDUType))
	engineID := report.EngineID
	require.NotEmpty(t, engineID)

	probe := snmpV3Probe(engineID, "admin")
	h = &recordingHoneypot{}
	require.NoError(t, HandleSNMP(context.Background(), src, dst, probe, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedSNMP)
	require.Len(t, events, 2)
	require.Equal(t, "admin", events[0].SecurityName)
	require.Equal(t, hex.EncodeToString(engineID), events[0].EngineID)
	require.Equal(t, snmp.StatusUnknownUserName, events[1].Status)
}

func TestHandleSNMPv3Truncated(t *testing.T) {
	swapSNMPAgent(t)
	src, dst := snmpAddrs()
	// A body cut inside the USM parameters keeps the msgGlobalData fields but
	// is not answered: the outer SEQUENCE length is fixed up so it parses.
	cut := append([]byte(nil), snmpV3Discovery[:30]...)
	cut[1] = byte(len(cut) - 2)
	h := &recordingHoneypot{}
	require.NoError(t, HandleSNMP(context.Background(), src, dst, cut, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Equal(t, []parsedSNMP{{Direction: "read", Command: "unknown", Version: "v3", MsgID: 0x44ba3355, MsgFlags: 4, Payload: cut}}, h.produced[0].decoded)

	// A bare v3 header is recorded without a reply.
	h = &recordingHoneypot{}
	v3 := []byte{0x30, 0x08, 0x02, 0x01, 0x03, 0x30, 0x03, 0x02, 0x01, 0x01}
	require.NoError(t, HandleSNMP(context.Background(), src, dst, v3, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	require.Equal(t, []parsedSNMP{{Direction: "read", Command: "unknown", Version: "v3", MsgID: 1, Payload: v3}}, h.produced[0].decoded)
}

func TestHandleSNMPMalformed(t *testing.T) {
	swapSNMPAgent(t)
	h := &recordingHoneypot{}
	src, dst := snmpAddrs()
	bad := snmpGetBulk[:30]

	require.NoError(t, HandleSNMP(context.Background(), src, dst, bad, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
	require.Equal(t, []parsedSNMP{{Direction: "read", Command: "unknown", Payload: bad}}, h.produced[0].decoded)
}

func TestHandleSNMPRoutedFromCatchAll(t *testing.T) {
	swapSNMPAgent(t)
	src, dst := snmpAddrs()
	// Any destination port reaches the snmp handler.
	dst.Port = 10161
	h := &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, snmpGetBulk, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "snmp", h.produced[0].handler)

	h = &recordingHoneypot{}
	require.NoError(t, HandleUDP(context.Background(), src, dst, []byte("\x30\x03\x02\x01\x01"), connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "udp", h.produced[0].handler)
}
