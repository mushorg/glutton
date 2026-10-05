package mctp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// read frame 1 of mushorg/glutton#73 (tcp/9000)
var issue73Read1 = []byte("REMOTE HI_SRDK_DEV_GetHddInfo MCTP/1.0\r\nCSeq:173\r\nAccept:text/HDP\r\nContent-Type:text/HDP\r\nFunc-Version:0x10\r\nContent-Length:15\r\n\r\nSegment-Num:0\r\n")

// request builds an MCTP request in the shape of the Kguard advisory, with
// synthetic segment data.
func request(function, cseq string, segments ...[]byte) []byte {
	var body strings.Builder
	body.WriteString("Segment-Num:" + strconv.Itoa(len(segments)) + "\r\n")
	for i, data := range segments {
		body.WriteString("Segment-Seq:" + strconv.Itoa(i+1) + "\r\nData-Length:" + strconv.Itoa(len(data)) + "\r\n\r\n")
		body.Write(data)
	}
	return []byte("REMOTE " + function + " MCTP/1.0\r\n" +
		"CSeq:" + cseq + "\r\n" +
		"Accept:text/HDP\r\n" +
		"Content-Type:text/HDP\r\n" +
		"Func-Version:0x10\r\n" +
		"Content-Length:" + strconv.Itoa(body.Len()) + "\r\n\r\n" +
		body.String())
}

func read(t *testing.T, data []byte, maxBody int) (Request, []byte, bool, error) {
	t.Helper()
	return ReadRequest(bufio.NewReader(bytes.NewReader(data)), maxBody)
}

func TestReadRequestIssue73(t *testing.T) {
	req, raw, truncated, err := read(t, issue73Read1, 1024)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, issue73Read1, raw)
	require.Equal(t, "REMOTE", req.Method)
	require.Equal(t, "HI_SRDK_DEV_GetHddInfo", req.Function)
	require.Equal(t, "MCTP/1.0", req.Version)
	require.Equal(t, "173", req.Header("CSeq"))
	require.Equal(t, "0x10", req.Header("func-version"))
	require.Equal(t, 15, req.ContentLength)
	require.Equal(t, []byte("Segment-Num:0\r\n"), req.Body)
	require.Empty(t, req.Segments)
}

func TestReadRequestSegments(t *testing.T) {
	// GetUserList in the advisory: Content-Length 51 with one 4-byte segment.
	data := request("HI_SRDK_SYS_USERMNG_GetUserList", "6", []byte{0, 0, 0, 1})
	require.Contains(t, string(data), "Content-Length:51\r\n")
	req, _, _, err := read(t, data, 1024)
	require.NoError(t, err)
	require.Equal(t, []Segment{{Seq: 1, Data: []byte{0, 0, 0, 1}}}, req.Segments)

	// SetMctpServerPort: Content-Length 49 with one 2-byte segment (port 9000).
	data = request("HI_SRDK_NET_SetMctpServerPort", "58", []byte{0x23, 0x28})
	require.Contains(t, string(data), "Content-Length:49\r\n")
	req, _, _, err = read(t, data, 1024)
	require.NoError(t, err)
	require.Equal(t, "HI_SRDK_NET_SetMctpServerPort", req.Function)
	require.Equal(t, []Segment{{Seq: 1, Data: []byte{0x23, 0x28}}}, req.Segments)

	// multi-segment body; data may contain CRLF
	data = request("HI_SRDK_NET_MOBILE_SetOwspAttr", "7", []byte("a\r\nb"), []byte{0xff})
	req, _, _, err = read(t, data, 1024)
	require.NoError(t, err)
	require.Equal(t, []Segment{{Seq: 1, Data: []byte("a\r\nb")}, {Seq: 2, Data: []byte{0xff}}}, req.Segments)
}

func TestReadRequestPipelined(t *testing.T) {
	stream := append(append([]byte{}, issue73Read1...), request("HI_SRDK_SYS_GetSystemAttr", "174")...)
	r := bufio.NewReader(bytes.NewReader(stream))

	first, raw, _, err := ReadRequest(r, 1024)
	require.NoError(t, err)
	require.Equal(t, issue73Read1, raw)
	require.Equal(t, "HI_SRDK_DEV_GetHddInfo", first.Function)

	second, _, _, err := ReadRequest(r, 1024)
	require.NoError(t, err)
	require.Equal(t, "HI_SRDK_SYS_GetSystemAttr", second.Function)
	require.Equal(t, "174", second.Header("CSeq"))

	_, raw, _, err = ReadRequest(r, 1024)
	require.ErrorIs(t, err, io.EOF)
	require.Empty(t, raw)
}

func TestReadRequestTruncated(t *testing.T) {
	data := request("HI_SRDK_NET_SetWebServerPort", "9", bytes.Repeat([]byte{0x41}, 100))
	req, raw, truncated, err := read(t, data, 32)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Len(t, req.Body, 32)
	require.Equal(t, len(data)-(req.ContentLength-32), len(raw))
}

func TestReadRequestBodyTooLarge(t *testing.T) {
	data := []byte("REMOTE HI_SRDK_DEV_SaveFlash MCTP/1.0\r\nContent-Length:99999999\r\n\r\nxx")
	_, _, truncated, err := read(t, data, 16)
	require.True(t, truncated)
	require.ErrorIs(t, err, ErrBodyTooLarge)
}

func TestReadRequestMalformed(t *testing.T) {
	cases := map[string][]byte{
		"not mctp":       []byte("GET / HTTP/1.1\r\n\r\n"),
		"short line":     []byte("REMOTE MCTP/1.0\r\n\r\n"),
		"bad header":     []byte("REMOTE f MCTP/1.0\r\nno-colon\r\n\r\n"),
		"bad length":     []byte("REMOTE f MCTP/1.0\r\nContent-Length:-1\r\n\r\n"),
		"too many hdrs":  []byte("REMOTE f MCTP/1.0\r\n" + strings.Repeat("X:1\r\n", maxHeaders+2) + "\r\n"),
		"line too long":  append([]byte("REMOTE "), bytes.Repeat([]byte("A"), 8192)...),
		"short body":     []byte("REMOTE f MCTP/1.0\r\nContent-Length:10\r\n\r\nabc"),
		"no blank line":  []byte("REMOTE f MCTP/1.0\r\nCSeq:1\r\n"),
		"no request eol": []byte("REMOTE f MCTP/1.0"),
		"missing body":   []byte("REMOTE f MCTP/1.0\r\nContent-Length:10\r\n\r\n"),
	}
	for name, data := range cases {
		_, raw, _, err := read(t, data, 1024)
		require.Error(t, err, name)
		require.NotEmpty(t, raw, name)
		require.False(t, errors.Is(err, io.EOF), name)
	}
}

func TestParseSegmentsBestEffort(t *testing.T) {
	require.Nil(t, parseSegments(nil))
	require.Nil(t, parseSegments([]byte("garbage")))
	// declared 2 segments, second one short
	body := []byte("Segment-Num:2\r\nSegment-Seq:1\r\nData-Length:1\r\n\r\nASegment-Seq:2\r\nData-Length:9\r\n\r\nB")
	require.Equal(t, []Segment{{Seq: 1, Data: []byte("A")}}, parseSegments(body))
}

func TestBuildResponse(t *testing.T) {
	require.Equal(t, "MCTP/1.0 200 OK\r\n"+
		"Content-Type:text/HDP\r\n"+
		"CSeq:173\r\n"+
		"Return-Code:0\r\n"+
		"Content-Length:15\r\n"+
		"\r\n"+
		"Segment-Num:0\r\n", string(BuildResponse("173", 0)))
}

func TestLooksLikeMCTP(t *testing.T) {
	require.True(t, LooksLikeMCTP(issue73Read1))
	require.True(t, LooksLikeMCTP([]byte("REMOTE ")))
	require.False(t, LooksLikeMCTP([]byte("REMOT")))
	require.False(t, LooksLikeMCTP([]byte("GET / HTTP/1.1")))
	require.False(t, LooksLikeMCTP([]byte{0x01, 0x01, 0x00, 0x01}))
}
