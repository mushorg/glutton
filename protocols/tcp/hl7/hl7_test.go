package hl7

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// synthetic ADT^A01 in the HL7 v2.5 shape; the patient data is made up
const adtA01 = "MSH|^~\\&|REGADT|GOODHOSP|LAB|LABFAC|20261017093000||ADT^A01^ADT_A01|MSG00042|P|2.5\r" +
	"EVN|A01|20261017093000\r" +
	"PID|1||100234^^^GOODHOSP^MR||DOE^JANE||19800101|F\r" +
	"PV1|1|I|WARD1^101^A\r"

func TestReadMessageFramed(t *testing.T) {
	wire := Frame([]byte(adtA01))
	r := bufio.NewReader(bytes.NewReader(append(wire, Frame([]byte("MSH|^~\\&|X"))...)))

	raw, msg, framed, truncated, err := ReadMessage(r, 1<<20)
	require.NoError(t, err)
	require.True(t, framed)
	require.False(t, truncated)
	require.Equal(t, wire, raw)
	require.Equal(t, adtA01, string(msg))

	raw, msg, framed, _, err = ReadMessage(r, 1<<20)
	require.NoError(t, err)
	require.True(t, framed)
	require.Equal(t, "\x0bMSH|^~\\&|X\x1c\r", string(raw))
	require.Equal(t, "MSH|^~\\&|X", string(msg))

	_, _, _, _, err = ReadMessage(r, 1<<20)
	require.ErrorIs(t, err, io.EOF)
}

func TestReadMessageFramedWithoutCR(t *testing.T) {
	// a missing CR after the end block leaves the next frame intact
	r := bufio.NewReader(strings.NewReader("\x0bMSH|A\x1c\x0bMSH|B\x1c\r"))
	raw, msg, _, _, err := ReadMessage(r, 1<<20)
	require.NoError(t, err)
	require.Equal(t, "\x0bMSH|A\x1c", string(raw))
	require.Equal(t, "MSH|A", string(msg))
	_, msg, framed, _, err := ReadMessage(r, 1<<20)
	require.NoError(t, err)
	require.True(t, framed)
	require.Equal(t, "MSH|B", string(msg))
}

func TestReadMessageSkipsLineEnds(t *testing.T) {
	// the CR of the previous frame arrived late, plus LFs from a raw sender
	r := bufio.NewReader(strings.NewReader("\r\n\x0bMSH|B\x1c\r"))
	raw, msg, framed, _, err := ReadMessage(r, 1<<20)
	require.NoError(t, err)
	require.True(t, framed)
	require.Equal(t, "\x0bMSH|B\x1c\r", string(raw))
	require.Equal(t, "MSH|B", string(msg))

	_, _, _, _, err = ReadMessage(bufio.NewReader(strings.NewReader("\r\n")), 1<<20)
	require.ErrorIs(t, err, io.EOF)
}

func TestReadMessageFramedPartial(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("\x0bMSH|^~\\&|A"))
	raw, msg, framed, _, err := ReadMessage(r, 1<<20)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.True(t, framed)
	require.Equal(t, "\x0bMSH|^~\\&|A", string(raw))
	require.Equal(t, "MSH|^~\\&|A", string(msg))
}

func TestReadMessageFramedTooLarge(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader(Frame(bytes.Repeat([]byte("A"), 100))))
	raw, msg, _, truncated, err := ReadMessage(r, 10)
	require.ErrorIs(t, err, ErrTooLarge)
	require.True(t, truncated)
	require.Len(t, msg, 10)
	require.Len(t, raw, 11)
}

func TestReadMessageBare(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(adtA01))
	raw, msg, framed, truncated, err := ReadMessage(r, 1<<20)
	require.NoError(t, err)
	require.False(t, framed)
	require.False(t, truncated)
	require.Equal(t, adtA01, string(raw))
	require.Equal(t, raw, msg)

	r = bufio.NewReader(strings.NewReader(adtA01))
	raw, _, _, truncated, err = ReadMessage(r, 8)
	require.ErrorIs(t, err, ErrTooLarge)
	require.True(t, truncated)
	require.Equal(t, adtA01[:8], string(raw))
}

func TestParseMSH(t *testing.T) {
	h, err := ParseMSH([]byte(adtA01))
	require.NoError(t, err)
	require.Equal(t, Header{
		FieldSep:             '|',
		Encoding:             `^~\&`,
		SendingApplication:   "REGADT",
		SendingFacility:      "GOODHOSP",
		ReceivingApplication: "LAB",
		ReceivingFacility:    "LABFAC",
		MessageCode:          "ADT",
		TriggerEvent:         "A01",
		ControlID:            "MSG00042",
		ProcessingID:         "P",
		Version:              "2.5",
	}, h)
	require.Equal(t, "ADT^A01", h.MessageType())
	require.Equal(t, []string{"MSH", "EVN", "PID", "PV1"}, SegmentIDs([]byte(adtA01), h.FieldSep))
}

func TestParseMSHVariants(t *testing.T) {
	// LF-separated (cat | nc), MSH-8 security, other separators
	h, err := ParseMSH([]byte("MSH#*~\\&#APP#FAC#####QRY*A19#Q1#P#2.3.1*X\nQRD#x\n"))
	require.NoError(t, err)
	require.Equal(t, byte('#'), h.FieldSep)
	require.Equal(t, "QRY^A19", h.MessageType())
	require.Equal(t, "2.3.1", h.Version)

	h, err = ParseMSH([]byte("MSH|^~\\&|A|B|C|D|20261017||ADT^A04|1|P|2.4|||||||||\r"))
	require.NoError(t, err)
	require.Empty(t, h.Security)

	h, err = ParseMSH([]byte("MSH|^~\\&|A|B|C|D||admin:secret|ADT^A04|7\r"))
	require.NoError(t, err)
	require.Equal(t, "admin:secret", h.Security)
	require.Empty(t, h.Version)

	h, err = ParseMSH([]byte("MSH|^~\\&|A\r"))
	require.NoError(t, err)
	require.Empty(t, h.MessageCode)
	require.Empty(t, h.ControlID)

	for _, bad := range []string{"", "\r\n", "PID|1", "MSH", "GET / HTTP/1.1\r\n"} {
		_, err := ParseMSH([]byte(bad))
		require.ErrorIs(t, err, ErrNoMSH, bad)
	}
}

func TestSegmentIDsCap(t *testing.T) {
	msg := strings.Repeat("OBX|1\r", 2*maxSegmentIDs)
	require.Len(t, SegmentIDs([]byte(msg), '|'), maxSegmentIDs)
	require.Equal(t, []string{"ZZZ", "A"}, SegmentIDs([]byte("ZZZZZ\rA|b"), 0))
}

func TestBuildACK(t *testing.T) {
	req, err := ParseMSH([]byte(adtA01))
	require.NoError(t, err)
	got := BuildACK(req, Ack{Code: "AA", ControlID: "8812", Timestamp: "20261017093001"})
	require.Equal(t, "MSH|^~\\&|LAB|LABFAC|REGADT|GOODHOSP|20261017093001||ACK^A01^ACK|8812|P|2.5\rMSA|AA|MSG00042\r", string(got))

	// v2.3 has no message structure component; AE carries an ERR segment
	req.Version = "2.3"
	got = BuildACK(req, Ack{Code: "AE", ControlID: "8813", Timestamp: "20261017093002", ErrorCode: ErrorRequiredField})
	require.Equal(t, "MSH|^~\\&|LAB|LABFAC|REGADT|GOODHOSP|20261017093002||ACK^A01|8813|P|2.3\r"+
		"MSA|AE|MSG00042\rERR|||101^Required field missing^HL70357|E\r", string(got))

	// no request header at all: defaults
	got = BuildACK(Header{}, Ack{Code: "AR", ControlID: "1", Timestamp: "T", ErrorCode: ErrorSegmentSequence})
	require.Equal(t, "MSH|^~\\&|||||T||ACK|1|P|2.5\rMSA|AR|\rERR|||100^Segment sequence error^HL70357|E\r", string(got))
}

func TestLooksLikeHL7(t *testing.T) {
	require.True(t, LooksLikeHL7([]byte("\x0bMSH|^~")))
	require.True(t, LooksLikeHL7([]byte("MSH|^~\\&|")))
	require.False(t, LooksLikeHL7([]byte("\x0bMS")))
	require.False(t, LooksLikeHL7([]byte("MSHello")))
	require.False(t, LooksLikeHL7([]byte("\x0bGET /")))
	require.False(t, LooksLikeHL7([]byte("GET / HTTP/1.1")))
}
