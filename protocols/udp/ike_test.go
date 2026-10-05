package udp

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// Ochi event 20d0edbf-d2c1-45ed-956b-fad6c3e84877: Censys IKEv2 IKE_SA_INIT on udp/500.
// read frame 1 (392 bytes)
var ikeCensysRead1 = []byte{
	0x78, 0x62, 0x9a, 0x0f, 0x5f, 0x3f, 0x16, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x88, 0x22, 0x00, 0x00, 0xec,
	0x00, 0x00, 0x00, 0xe8, 0x01, 0x01, 0x00, 0x1c, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x01,
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x03,
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x06,
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x07, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x08,
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x09, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x0b,
	0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x0c, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x0d,
	0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02,
	0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x01,
	0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x03,
	0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x05,
	0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x01,
	0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x05,
	0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x0e, 0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x0f,
	0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x10, 0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x11,
	0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x12, 0x28, 0x00, 0x00, 0x68, 0x00, 0x01, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
	0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
	0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
	0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
	0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
	0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x18, 0x99, 0x19, 0x13, 0x3e, 0xd6, 0xed, 0x4a, 0xf4, 0xdc, 0x18, 0x92, 0xe6,
	0x96, 0xca, 0xd7, 0x5f, 0x74, 0x73, 0x09, 0x15,
}

// ikeInvalidKE is the expected reply to ikeCensysRead1: INVALID_KE_PAYLOAD asking for MODP_2048.
var ikeInvalidKE, _ = hex.DecodeString("78629a0f5f3f164f0000000000000000" + "2920222000000000" + "00000026" + "0000000a00000011000e")

var ikeCensysRead = parsedIKE{
	Direction:  "read",
	Command:    "IKE_SA_INIT",
	Version:    "2.0",
	SPIi:       "78629a0f5f3f164f",
	SPIr:       "0000000000000000",
	Encryption: []string{"DES_IV64", "DES", "3DES", "RC5", "CAST", "BLOWFISH", "3IDEA", "DES_IV32", "NULL", "AES_CBC", "AES_CTR"},
	PRF:        []string{"HMAC_MD5", "HMAC_SHA1"},
	Integrity:  []string{"NONE", "HMAC_MD5_96", "HMAC_SHA1_96", "DES_MAC", "KPDK_MD5", "AES_XCBC_96"},
	DHGroups:   []string{"NONE", "MODP_768", "MODP_1024", "MODP_1536", "MODP_2048", "MODP_3072", "MODP_4096", "MODP_6144", "MODP_8192"},
	KEGroup:    "MODP_768",
}

func ikeAddrs(port int) (*net.UDPAddr, *net.UDPAddr) {
	return &net.UDPAddr{IP: net.ParseIP("66.132.186.239"), Port: 47886}, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: port}
}

func TestHandleIKECensysInvalidKE(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ikeAddrs(500)

	require.NoError(t, HandleIKE(context.Background(), src, dst, ikeCensysRead1, connection.Metadata{}, testLogger{}, h))

	require.Equal(t, [][]byte{ikeInvalidKE}, h.replies)
	require.Len(t, h.produced, 1)
	require.Equal(t, "ike", h.produced[0].handler)
	require.Equal(t, ikeCensysRead1, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)

	read := ikeCensysRead
	read.Payload = ikeCensysRead1
	require.Equal(t, []parsedIKE{
		read,
		{
			Direction:  "write",
			Command:    "IKE_SA_INIT",
			Status:     "INVALID_KE_PAYLOAD",
			Version:    "2.0",
			SPIi:       "78629a0f5f3f164f",
			SPIr:       "0000000000000000",
			Encryption: []string{"3DES"},
			PRF:        []string{"HMAC_SHA1"},
			Integrity:  []string{"HMAC_SHA1_96"},
			DHGroups:   []string{"MODP_2048"},
			Payload:    ikeInvalidKE,
		},
	}, h.produced[0].decoded)
}

func TestHandleIKENATTMarker(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ikeAddrs(4500)
	datagram := append([]byte{0, 0, 0, 0}, ikeCensysRead1...)

	require.NoError(t, HandleIKE(context.Background(), src, dst, datagram, connection.Metadata{}, testLogger{}, h))

	// the reply keeps the non-ESP marker
	require.Equal(t, [][]byte{append([]byte{0, 0, 0, 0}, ikeInvalidKE...)}, h.replies)
	events := h.produced[0].decoded.([]parsedIKE)
	require.Len(t, events, 2)
	require.True(t, events[0].NATT)
	require.Equal(t, datagram, events[0].Payload)
	require.Equal(t, "IKE_SA_INIT", events[0].Command)
	require.True(t, events[1].NATT)
}

func TestHandleIKEv1NoReply(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ikeAddrs(500)
	v1 := append([]byte{}, ikeCensysRead1...)
	v1[17] = 0x10 // IKEv1
	v1[18] = 2    // Identity Protection (Main Mode)

	require.NoError(t, HandleIKE(context.Background(), src, dst, v1, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedIKE)
	require.Len(t, events, 1)
	require.Equal(t, "1.0", events[0].Version)
	require.Equal(t, "IDENTITY_PROTECTION", events[0].Command)
	require.Empty(t, events[0].Encryption, "IKEv1 SA payloads are not decoded")
}

func TestHandleIKETruncatedStillProduces(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ikeAddrs(500)
	short := ikeCensysRead1[:100]

	require.NoError(t, HandleIKE(context.Background(), src, dst, short, connection.Metadata{}, testLogger{}, h))
	require.Empty(t, h.replies)
	events := h.produced[0].decoded.([]parsedIKE)
	require.Len(t, events, 1)
	require.Equal(t, "IKE_SA_INIT", events[0].Command, "header decoded despite truncation")
	require.Equal(t, short, events[0].Payload)

	h = &recordingHoneypot{}
	require.NoError(t, HandleIKE(context.Background(), src, dst, []byte{1, 2, 3}, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, []parsedIKE{{Direction: "read", Payload: []byte{1, 2, 3}}}, h.produced[0].decoded)
}

func TestHandleIKEOversizeCapped(t *testing.T) {
	h := &recordingHoneypot{}
	src, dst := ikeAddrs(500)
	big := append(append([]byte{}, ikeCensysRead1...), bytes.Repeat([]byte{0x41}, maxIKEPayload)...)

	require.NoError(t, HandleIKE(context.Background(), src, dst, big, connection.Metadata{}, testLogger{}, h))
	events := h.produced[0].decoded.([]parsedIKE)
	require.Len(t, events[0].Payload, maxIKEPayload)
	require.True(t, events[0].Truncated)
}

func TestHandleIKEFullResponse(t *testing.T) {
	prev := ikeRand
	ikeRand = bytes.NewReader(bytes.Repeat([]byte{0x5a}, 512))
	t.Cleanup(func() { ikeRand = prev })

	// rewrite the Censys KE group to MODP_2048: the responder now answers in full
	req := append([]byte{}, ikeCensysRead1...)
	keOff := bytes.Index(req, []byte{0x28, 0x00, 0x00, 0x68}) + 4
	req[keOff], req[keOff+1] = 0x00, 0x0e

	h := &recordingHoneypot{}
	src, dst := ikeAddrs(500)
	require.NoError(t, HandleIKE(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.replies, 1)
	events := h.produced[0].decoded.([]parsedIKE)
	require.Len(t, events, 2)
	require.Equal(t, "MODP_2048", events[0].KEGroup)
	require.Equal(t, parsedIKE{
		Direction:  "write",
		Command:    "IKE_SA_INIT",
		Status:     "IKE_SA_INIT",
		Version:    "2.0",
		SPIi:       "78629a0f5f3f164f",
		SPIr:       "5a5a5a5a5a5a5a5a",
		Encryption: []string{"3DES"},
		PRF:        []string{"HMAC_SHA1"},
		Integrity:  []string{"HMAC_SHA1_96"},
		DHGroups:   []string{"MODP_2048"},
		KEGroup:    "MODP_2048",
		Payload:    h.replies[0],
	}, events[1])
	// header: SPIs, SA first, v2.0, IKE_SA_INIT, response flag
	require.Equal(t, []byte{0x21, 0x20, 0x22, 0x20}, h.replies[0][16:20])
}

func TestHandleUDPReroutesIKE(t *testing.T) {
	t.Chdir(t.TempDir()) // the generic handler stores payloads in ./payloads
	h := &recordingHoneypot{}
	src, dst := ikeAddrs(9999)
	require.NoError(t, HandleUDP(context.Background(), src, dst, ikeCensysRead1, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "ike", h.produced[0].handler)

	// a near miss (length field off by one) stays generic
	h = &recordingHoneypot{}
	odd := append(append([]byte{}, ikeCensysRead1...), 0)
	require.NoError(t, HandleUDP(context.Background(), src, dst, odd, connection.Metadata{}, testLogger{}, h))
	require.Equal(t, "udp", h.produced[0].handler)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
}
