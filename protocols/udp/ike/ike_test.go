package ike

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Ochi event 20d0edbf-d2c1-45ed-956b-fad6c3e84877: Censys IKEv2 IKE_SA_INIT on udp/500.
// read frame 1 (392 bytes)
var censysRead1 = []byte{
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

// counter is a deterministic random source: 0x01, 0x02, ...
type counter struct{ n byte }

func (c *counter) Read(p []byte) (int, error) {
	for i := range p {
		c.n++
		p[i] = c.n
	}
	return len(p), nil
}

func TestParseCensysSAInit(t *testing.T) {
	m, err := Parse(censysRead1)
	require.NoError(t, err)
	require.Equal(t, "78629a0f5f3f164f", hex.EncodeToString(m.SPIi[:]))
	require.Equal(t, [8]byte{}, m.SPIr)
	require.Equal(t, "2.0", m.VersionString())
	require.Equal(t, "IKE_SA_INIT", ExchangeName(m.Exchange))
	require.Equal(t, flagInitiator, m.Flags)
	require.Equal(t, uint32(392), m.Length)
	require.Len(t, m.Proposals, 1)
	require.Equal(t, byte(1), m.Proposals[0].Num)
	require.Equal(t, protocolIKE, m.Proposals[0].Protocol)
	require.Len(t, m.Proposals[0].Transforms, 28)
	require.Equal(t, []string{"DES_IV64", "DES", "3DES", "RC5", "CAST", "BLOWFISH", "3IDEA", "DES_IV32", "NULL", "AES_CBC", "AES_CTR"}, m.Offered(TransformENCR))
	require.Equal(t, []string{"HMAC_MD5", "HMAC_SHA1"}, m.Offered(TransformPRF))
	require.Equal(t, []string{"NONE", "HMAC_MD5_96", "HMAC_SHA1_96", "DES_MAC", "KPDK_MD5", "AES_XCBC_96"}, m.Offered(TransformINTEG))
	require.Equal(t, []string{"NONE", "MODP_768", "MODP_1024", "MODP_1536", "MODP_2048", "MODP_3072", "MODP_4096", "MODP_6144", "MODP_8192"}, m.Offered(TransformDH))
	require.True(t, m.HasKE)
	require.Equal(t, uint16(1), m.KEGroup)
	require.Equal(t, "9919133ed6ed4af4dc1892e696cad75f74730915", hex.EncodeToString(m.Nonce))
	require.Empty(t, m.VendorIDs)
}

func TestCensysGetsInvalidKEPayload(t *testing.T) {
	m, err := Parse(censysRead1)
	require.NoError(t, err)

	c, ok := Choose(m)
	require.True(t, ok)
	// AES_CBC is offered without a key length, so 3DES is the best usable cipher
	require.Equal(t, []string{"3DES", "HMAC_SHA1", "HMAC_SHA1_96", "MODP_2048"}, names(c.Transforms()))

	r, ok, err := BuildReply(m, &counter{})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "INVALID_KE_PAYLOAD", r.Status)
	want, _ := hex.DecodeString(
		"78629a0f5f3f164f" + "0000000000000000" + // SPIi echoed, SPIr zero
			"29" + "20" + "22" + "20" + "00000000" + "00000026" + // Notify, v2.0, IKE_SA_INIT, response, msg 0, len 38
			"0000000a" + "0000" + "0011" + "000e") // N: no next, len 10, proto 0, SPI size 0, type 17, group 14
	require.Equal(t, want, r.Data)

	parsed, err := Parse(r.Data)
	require.NoError(t, err)
	require.Equal(t, []string{"INVALID_KE_PAYLOAD"}, parsed.NotifyNames())
}

func names(ts []Transform) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Name())
	}
	return out
}

// buildRequest builds an IKE_SA_INIT request with one proposal and a KE payload.
func buildRequest(t *testing.T, transforms []Transform, keGroup uint16) []byte {
	t.Helper()
	m := Message{SPIi: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	c := Choice{ProposalNum: 1}
	sa := saPayloadFrom(c.ProposalNum, transforms)
	ke := binary.BigEndian.AppendUint16(nil, keGroup)
	ke = append(ke, 0, 0)
	ke = append(ke, bytes.Repeat([]byte{0xaa}, 32)...)
	var body []byte
	body = appendPayload(body, payloadKE, sa)
	body = appendPayload(body, payloadNonce, ke)
	body = appendPayload(body, payloadNone, bytes.Repeat([]byte{0xbb}, 16))
	data := header(m, [8]byte{}, payloadSA, body)
	data[19] = flagInitiator
	return data
}

func saPayloadFrom(num byte, ts []Transform) []byte {
	c := Choice{ProposalNum: num}
	// reuse the response encoder: it writes the transforms it is given in order
	c.ENCR, c.PRF, c.DH = ts[0], ts[1], ts[len(ts)-1]
	if len(ts) == 4 {
		c.INTEG = &ts[2]
	}
	return saPayload(c)
}

func TestFullSAInitResponse(t *testing.T) {
	offer := []Transform{{TransformENCR, 12, 256}, {TransformPRF, 5, 0}, {TransformINTEG, 12, 0}, {TransformDH, 14, 0}}
	m, err := Parse(buildRequest(t, offer, 14))
	require.NoError(t, err)

	r, ok, err := BuildReply(m, &counter{})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "IKE_SA_INIT", r.Status)
	require.Equal(t, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, r.SPIr)

	resp, err := Parse(r.Data)
	require.NoError(t, err)
	require.Equal(t, m.SPIi, resp.SPIi)
	require.Equal(t, r.SPIr, resp.SPIr)
	require.Equal(t, flagResponse, resp.Flags)
	require.Equal(t, uint32(len(r.Data)), resp.Length)
	require.Len(t, resp.Proposals, 1)
	require.Equal(t, []string{"AES_CBC_256", "HMAC_SHA2_256", "HMAC_SHA2_256_128", "MODP_2048"}, names(resp.Proposals[0].Transforms))
	require.True(t, resp.HasKE)
	require.Equal(t, uint16(14), resp.KEGroup)
	require.Len(t, resp.Nonce, 32)
	// counter source: SPIr 1..8, KE 9..264 (wraps), nonce follows
	require.Equal(t, byte(9), r.Data[bytes.Index(r.Data, []byte{0, 14, 0, 0})+4])
}

func TestAEADOmitsIntegrity(t *testing.T) {
	offer := []Transform{{TransformENCR, 20, 128}, {TransformPRF, 2, 0}, {TransformDH, 19, 0}}
	m, err := Parse(buildRequest(t, offer, 19))
	require.NoError(t, err)
	r, ok, err := BuildReply(m, &counter{})
	require.NoError(t, err)
	require.True(t, ok)
	resp, err := Parse(r.Data)
	require.NoError(t, err)
	require.Equal(t, []string{"AES_GCM_16_128", "HMAC_SHA1", "ECP_256"}, names(resp.Proposals[0].Transforms))
}

func TestNoProposalChosen(t *testing.T) {
	offer := []Transform{{TransformENCR, 2, 0}, {TransformPRF, 1, 0}, {TransformINTEG, 1, 0}, {TransformDH, 2, 0}}
	m, err := Parse(buildRequest(t, offer, 2))
	require.NoError(t, err)
	r, ok, err := BuildReply(m, &counter{})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "NO_PROPOSAL_CHOSEN", r.Status)
	resp, err := Parse(r.Data)
	require.NoError(t, err)
	require.Equal(t, []string{"NO_PROPOSAL_CHOSEN"}, resp.NotifyNames())
	require.Equal(t, [8]byte{}, resp.SPIr)
}

func TestNoReplyOutsideSAInitRequest(t *testing.T) {
	resp := append([]byte{}, censysRead1...)
	resp[19] = flagResponse
	auth := append([]byte{}, censysRead1...)
	auth[18] = ExchangeAuth
	v1 := append([]byte{}, censysRead1...)
	v1[17] = VersionV1
	for _, data := range [][]byte{resp, auth, v1} {
		m, err := Parse(data)
		require.NoError(t, err)
		_, ok, err := BuildReply(m, &counter{})
		require.NoError(t, err)
		require.False(t, ok)
	}
}

func TestParseErrors(t *testing.T) {
	_, err := Parse(censysRead1[:20])
	require.ErrorIs(t, err, ErrTruncated)

	m, err := Parse(censysRead1[:200])
	require.ErrorIs(t, err, ErrTruncated)
	require.Equal(t, "IKE_SA_INIT", ExchangeName(m.Exchange), "header still decoded")

	bad := append([]byte{}, censysRead1...)
	bad[30], bad[31] = 0x0f, 0xff // SA payload length past the end
	_, err = Parse(bad)
	require.ErrorIs(t, err, ErrMalformed)
}

func TestNonESPMarkerAndLooksLike(t *testing.T) {
	require.True(t, LooksLikeIKE(censysRead1))

	natt := append([]byte{0, 0, 0, 0}, censysRead1...)
	stripped, ok := StripNonESPMarker(natt)
	require.True(t, ok)
	require.Equal(t, censysRead1, stripped)
	require.True(t, LooksLikeIKE(natt))

	_, ok = StripNonESPMarker(censysRead1)
	require.False(t, ok)

	require.False(t, LooksLikeIKE(censysRead1[:100]), "length mismatch")
	require.False(t, LooksLikeIKE(append(append([]byte{}, censysRead1...), 0)), "trailing byte")
	odd := append([]byte{}, censysRead1...)
	odd[17] = 0x30
	require.False(t, LooksLikeIKE(odd), "unknown version")
	require.False(t, LooksLikeIKE([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")))
}

func TestVendorIDs(t *testing.T) {
	m := Message{SPIi: [8]byte{9}}
	vid, _ := hex.DecodeString("4048b7d56ebce88525e7de7f00d6c2d3")
	body := appendPayload(nil, payloadNone, vid)
	data := header(m, [8]byte{}, payloadVendorID, body)
	data[18] = ExchangeInformational
	parsed, err := Parse(data)
	require.NoError(t, err)
	require.Equal(t, []string{"4048b7d56ebce88525e7de7f00d6c2d3"}, parsed.VendorIDHex())
}
