package dns

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// cloudflare.com A IN with an EDNS0 OPT record (UDP size 1232), as sent by
// the infrawatch resolver probe to tcp/53 (without the 2-byte length prefix).
const infrawatchQuery = "f50f010000010000000000010a636c6f7564666c61726503636f6d000001000100002904d0000000000000"

func TestParseQuery(t *testing.T) {
	q, err := Parse(mustHex(t, infrawatchQuery))
	require.NoError(t, err)
	require.Equal(t, uint16(0xf50f), q.ID)
	require.False(t, q.Response)
	require.True(t, q.RD)
	require.Equal(t, "cloudflare.com", q.Name)
	require.Equal(t, "A", TypeName(q.Type))
	require.Equal(t, uint16(1), q.Class)
	require.True(t, q.EDNS)
	require.Equal(t, uint8(0), q.Version)
}

func TestBuildResponseRefused(t *testing.T) {
	query := mustHex(t, infrawatchQuery)
	q, err := Parse(query)
	require.NoError(t, err)
	rcode := Refusal(q, err)
	require.Equal(t, RcodeRefused, rcode)

	resp := BuildResponse(q, rcode, err)
	// ID echoed, QR|RD|REFUSED, one question, one OPT, RA clear
	require.Equal(t, "f50f81050001000000000001", hex.EncodeToString(resp[:12]))
	require.Equal(t, q.Question, resp[12:12+len(q.Question)])
	require.Equal(t, "00002904d0000000000000", hex.EncodeToString(resp[12+len(q.Question):]))
	require.LessOrEqual(t, len(resp), len(query), "reply must not exceed the query")
}

func TestBuildResponseWithoutEDNS(t *testing.T) {
	// example.org AXFR IN, no OPT
	query := mustHex(t, "123400000001000000000000"+"076578616d706c65036f726700"+"00fc0001")
	q, err := Parse(query)
	require.NoError(t, err)
	require.Equal(t, "AXFR", TypeName(q.Type))
	require.False(t, q.RD)
	require.False(t, q.EDNS)
	resp := BuildResponse(q, Refusal(q, err), err)
	require.Equal(t, "123480050001000000000000", hex.EncodeToString(resp[:12]))
	require.Len(t, resp, len(query))
}

func TestRefusalCodes(t *testing.T) {
	q, err := Parse(mustHex(t, infrawatchQuery))
	require.NoError(t, err)

	q.Opcode = 5
	require.Equal(t, RcodeNotImp, Refusal(q, nil))
	resp := BuildResponse(q, RcodeNotImp, nil)
	require.Equal(t, byte(0xa9), resp[2], "QR, opcode 5 and RD")
	require.Equal(t, byte(RcodeNotImp), resp[3]&0x0f)

	q.Opcode = 0
	q.Version = 1
	require.Equal(t, RcodeBadVers, Refusal(q, nil))
	resp = BuildResponse(q, RcodeBadVers, nil)
	require.Equal(t, byte(0), resp[3]&0x0f, "low rcode bits")
	require.Equal(t, byte(1), resp[len(resp)-6], "extended rcode in OPT TTL")
}

func TestParseMalformed(t *testing.T) {
	_, err := Parse([]byte{0, 1, 2})
	require.ErrorIs(t, err, ErrShort)

	// header only, QDCOUNT 1 but no question
	q, err := Parse(mustHex(t, "abcd01000001000000000000"))
	require.ErrorIs(t, err, ErrMalformed)
	require.Equal(t, uint16(0xabcd), q.ID)
	resp := BuildResponse(q, Refusal(q, err), err)
	require.Equal(t, "abcd81010000000000000000", hex.EncodeToString(resp))

	// QDCOUNT 0
	_, err = Parse(mustHex(t, "abcd01000000000000000000"))
	require.ErrorIs(t, err, ErrMalformed)

	// compression pointer in the question, oversized label, name cut short
	header := mustHex(t, "abcd01000001000000000000")
	for name, question := range map[string][]byte{
		"pointer":   mustHex(t, "c00c00010001"),
		"label":     append([]byte{0x40}, make([]byte, 70)...),
		"truncated": mustHex(t, "03777777"),
		"no type":   mustHex(t, "03777777"+"00"),
	} {
		_, err = Parse(append(append([]byte(nil), header...), question...))
		require.ErrorIs(t, err, ErrMalformed, name)
	}
}

func TestParseResponseBit(t *testing.T) {
	msg := mustHex(t, infrawatchQuery)
	msg[2] |= 0x80
	q, err := Parse(msg)
	require.NoError(t, err)
	require.True(t, q.Response)
}

func TestEscapeName(t *testing.T) {
	// label "a.b" (with a dot byte) and a 0x01 byte
	raw := mustHex(t, "abcd0100000100000000000003612e62"+"0101"+"00"+"00010001")
	// 03 'a' '.' 'b' | 01 0x01 | 00
	q, err := Parse(raw)
	require.NoError(t, err)
	require.Equal(t, `a\046b.\001`, q.Name)
}

func TestNames(t *testing.T) {
	require.Equal(t, "TYPE65280", TypeName(65280))
	require.Equal(t, "CH", ClassName(3))
	require.Equal(t, "CLASS99", ClassName(99))
	require.Equal(t, "REFUSED", RcodeName(RcodeRefused))
	require.Equal(t, "RCODE9", RcodeName(9))
}
