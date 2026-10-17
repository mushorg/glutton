package sip

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/require"
)

var streamRegister = "REGISTER sip:1.2.3.4 SIP/2.0\r\nVia: SIP/2.0/TCP 5.6.7.8:5060;branch=z9hG4bK1\r\nFrom: <sip:100@1.2.3.4>;tag=a\r\nTo: <sip:100@1.2.3.4>\r\nCall-ID: c1\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n"

func readAll(t *testing.T, r *bufio.Reader, maxBody int) []StreamMessage {
	t.Helper()
	var msgs []StreamMessage
	for {
		m, err := ReadStreamMessage(r, maxBody)
		if err == io.EOF {
			return msgs
		}
		require.NoError(t, err)
		msgs = append(msgs, m)
	}
}

func TestReadStreamMessageSplitReads(t *testing.T) {
	r := bufio.NewReader(iotest.OneByteReader(bytes.NewReader(pplsipInvite)))
	msgs := readAll(t, r, 4096)
	require.Equal(t, []StreamMessage{{Raw: pplsipInvite}}, msgs)
}

func TestReadStreamMessagePipelined(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(streamRegister + string(pplsipInvite)))
	msgs := readAll(t, r, 4096)
	require.Equal(t, []StreamMessage{{Raw: []byte(streamRegister)}, {Raw: pplsipInvite}}, msgs)
}

func TestReadStreamMessageKeepalive(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("\r\n\r\n" + streamRegister))
	msgs := readAll(t, r, 4096)
	require.Equal(t, []StreamMessage{
		{Raw: []byte("\r\n\r\n"), Keepalive: true},
		{Raw: []byte(streamRegister)},
	}, msgs)
}

func TestReadStreamMessageBareLFAndCompactLength(t *testing.T) {
	msg := "MESSAGE sip:100@1.2.3.4 SIP/2.0\nVia: SIP/2.0/TCP 5.6.7.8:5060;branch=z9hG4bK1\nl: 5\n\nhello"
	r := bufio.NewReader(strings.NewReader(msg + streamRegister))
	msgs := readAll(t, r, 4096)
	require.Equal(t, []StreamMessage{{Raw: []byte(msg)}, {Raw: []byte(streamRegister)}}, msgs)
}

func TestReadStreamMessageMissingContentLength(t *testing.T) {
	msg := strings.Replace(streamRegister, "Content-Length: 0\r\n", "", 1)
	r := bufio.NewReader(strings.NewReader(msg + streamRegister))
	msgs := readAll(t, r, 4096)
	require.Equal(t, []StreamMessage{{Raw: []byte(msg)}, {Raw: []byte(streamRegister)}}, msgs)
}

func TestReadStreamMessageTruncatesBody(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(string(pplsipInvite) + streamRegister))
	msgs := readAll(t, r, 10)
	headerLen := bytes.Index(pplsipInvite, []byte("\r\n\r\n")) + 4
	require.Equal(t, []StreamMessage{
		{Raw: pplsipInvite[:headerLen+10], Truncated: true},
		{Raw: []byte(streamRegister)},
	}, msgs)
}

func TestReadStreamMessageErrors(t *testing.T) {
	_, err := ReadStreamMessage(bufio.NewReader(strings.NewReader("INVITE sip:1@x SIP/2.0\r\nX: "+strings.Repeat("a", maxStreamHeader)+"\r\n\r\n")), 4096)
	require.ErrorIs(t, err, ErrHeaderTooLarge)

	for _, cl := range []string{"abc", "-1", "65537"} {
		m, err := ReadStreamMessage(bufio.NewReader(strings.NewReader("INVITE sip:1@x SIP/2.0\r\nContent-Length: "+cl+"\r\n\r\n")), 4096)
		require.ErrorIs(t, err, ErrContentLength, cl)
		require.NotEmpty(t, m.Raw)
	}

	// EOF in the middle of the body keeps what arrived
	m, err := ReadStreamMessage(bufio.NewReader(bytes.NewReader(pplsipInvite[:len(pplsipInvite)-5])), 4096)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, pplsipInvite[:len(pplsipInvite)-5], m.Raw)

	// EOF in the headers
	m, err = ReadStreamMessage(bufio.NewReader(strings.NewReader("OPTIONS sip:1@x SIP/2.0\r\nVia: x")), 4096)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, []byte("OPTIONS sip:1@x SIP/2.0\r\nVia: x"), m.Raw)
}

func TestReadStreamMessageLinesLongerThanBuffer(t *testing.T) {
	// header lines longer than the reader's buffer are reassembled: the
	// Content-Length is found, and a long line's tail is not a header
	line := "X-Pad: " + strings.Repeat("a", 20) + "Content-Length: 99\r\n"
	msg := "MESSAGE sip:1@x SIP/2.0\r\n" + line + "Content-Length: 5\r\n\r\nhello"
	r := bufio.NewReaderSize(strings.NewReader(msg+streamRegister), 16)
	msgs := readAll(t, r, 4096)
	require.Equal(t, []StreamMessage{{Raw: []byte(msg)}, {Raw: []byte(streamRegister)}}, msgs)
}
