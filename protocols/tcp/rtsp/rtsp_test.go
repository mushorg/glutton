package rtsp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// read frame 1 of ochi event f30046fd-0bb9-4f7c-b9c3-e25df4ddcff5 (tcp/10554)
var ochiOptions = []byte("OPTIONS rtsp://1.2.3.4:10554 RTSP/1.0\r\nCSeq: 1\r\n\r\n")

func fixedResponder() *Responder {
	return &Responder{
		Server: "Rtsp Server/3.0",
		Realm:  "Login to 7K02D8APAZ1C3F9",
		Nonce:  "00112233445566778899aabbccddeeff",
		Now:    func() time.Time { return time.Date(2026, 10, 10, 21, 44, 20, 0, time.UTC) },
	}
}

func TestLooksLikeRTSP(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{string(ochiOptions), true},
		{"DESCRIBE rtsp://1.2.3.4/Streaming/Channels/101 RTSP/1.0\r\n", true},
		{"PLAY rtsp://1.2.3.4/live RTSP/1.0\n", true},
		{"OPTIONS * RTSP/1.0\r\n", true},
		{"DESCRIBE rtsp://1.2.3.4/a/very/long/uri/cut/by/the/peek", true},
		{"OPTIONS rtsp://1.2.3.4:554", true},
		{"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", false},
		{"OPTIONS / HTTP/1.0\r\n", false},
		{"GET / HTTP/1.1\r\n", false},
		{"DESCRIBE /path HTTP/1.1\r\n", false},
		{"OPTIONS rtsp://1.2.3.4\r\n", false},
		{"REMOTE HI_SRDK_DEV_GetHddInfo MCTP/1.0\r\n", false},
		{"", false},
	} {
		require.Equal(t, tc.want, LooksLikeRTSP([]byte(tc.in)), tc.in)
	}
}

func TestMayStart(t *testing.T) {
	for _, in := range []string{"O", "OPTI", "DESC", "SETU", "PLAY", "PAUS", "TEAR", "GET_", "SET_", "ANNO", "RECO"} {
		require.True(t, MayStart([]byte(in)), in)
	}
	for _, in := range []string{"", "GET ", "POST", "PUT ", "HEAD", "\x16\x03\x01\x00", "SSH-", "OPTX"} {
		require.False(t, MayStart([]byte(in)), in)
	}
}

func TestReadRequestOchiOptions(t *testing.T) {
	req, raw, truncated, err := ReadRequest(bufio.NewReader(bytes.NewReader(ochiOptions)), 1024)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, ochiOptions, raw)
	require.Equal(t, "OPTIONS", req.Method)
	require.Equal(t, "rtsp://1.2.3.4:10554", req.URI)
	require.Equal(t, Version, req.Version)
	require.Equal(t, "1", req.Header("cseq"))
	require.Equal(t, "/", req.Path())
	require.Empty(t, req.URIUsername())
}

func TestReadRequestBodyAndPipelining(t *testing.T) {
	announce := "ANNOUNCE rtsp://1.2.3.4/live RTSP/1.0\r\nCSeq: 2\r\nContent-Length: 4\r\n\r\nv=0\n"
	next := "OPTIONS * RTSP/1.0\r\nCSeq: 3\r\n\r\n"
	r := bufio.NewReader(strings.NewReader(announce + next))

	req, raw, _, err := ReadRequest(r, 1024)
	require.NoError(t, err)
	require.Equal(t, []byte("v=0\n"), req.Body)
	require.Equal(t, announce, string(raw))

	req, raw, _, err = ReadRequest(r, 1024)
	require.NoError(t, err)
	require.Equal(t, "OPTIONS", req.Method)
	require.Equal(t, "*", req.Path())
	require.Equal(t, next, string(raw))

	_, raw, _, err = ReadRequest(r, 1024)
	require.ErrorIs(t, err, io.EOF)
	require.Empty(t, raw)
}

func TestReadRequestTruncatedBody(t *testing.T) {
	in := "SET_PARAMETER rtsp://1.2.3.4/ RTSP/1.0\r\nCSeq: 4\r\nContent-Length: 10\r\n\r\n0123456789OPTIONS * RTSP/1.0\r\nCSeq: 5\r\n\r\n"
	r := bufio.NewReader(strings.NewReader(in))
	req, raw, truncated, err := ReadRequest(r, 4)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Equal(t, []byte("0123"), req.Body)
	require.True(t, strings.HasSuffix(string(raw), "\r\n\r\n0123"))

	// the skipped bytes keep the stream in sync
	req, _, _, err = ReadRequest(r, 4)
	require.NoError(t, err)
	require.Equal(t, "5", req.Header("CSeq"))
}

func TestReadRequestErrors(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want error
	}{
		{"GET / HTTP/1.1\r\n\r\n", ErrMalformed},
		{"OPTIONS\r\n\r\n", ErrMalformed},
		{"OPTIONS * RTSP/1.0\r\nContent-Length: x\r\n\r\n", ErrMalformed},
		{"OPTIONS * RTSP/1.0\r\nContent-Length: 99999999\r\n\r\n", ErrBodyTooLarge},
		{"OPTIONS * RTSP/1.0\r\n" + strings.Repeat("X-A: b\r\n", maxHeaders+2) + "\r\n", ErrMalformed},
		{"OPTIONS /" + strings.Repeat("a", 5000) + " RTSP/1.0\r\n\r\n", ErrLineTooLong},
		{"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n", io.ErrUnexpectedEOF},
		{"OPTIONS * RTSP", io.ErrUnexpectedEOF},
	} {
		_, raw, _, err := ReadRequest(bufio.NewReader(strings.NewReader(tc.in)), 1024)
		require.True(t, errors.Is(err, tc.want), "%q: %v", tc.in, err)
		require.NotEmpty(t, raw, tc.in)
	}
}

func TestReadRequestSkipsHeaderWithoutColon(t *testing.T) {
	req, _, _, err := ReadRequest(bufio.NewReader(strings.NewReader("OPTIONS * RTSP/1.0\r\ngarbage\r\nCSeq: 7\r\n\r\n")), 1024)
	require.NoError(t, err)
	require.Equal(t, "7", req.Header("CSeq"))
}

func TestURIUsername(t *testing.T) {
	req := Request{URI: "rtsp://admin:12345@1.2.3.4:554/Streaming/Channels/101"}
	require.Equal(t, "admin", req.URIUsername())
	require.Equal(t, "/Streaming/Channels/101", req.Path())
}

func TestParseAuthorization(t *testing.T) {
	// admin:12345
	basic := ParseAuthorization("Basic YWRtaW46MTIzNDU=")
	require.Equal(t, Auth{Scheme: "basic", Username: "admin"}, basic)

	digest := ParseAuthorization(`Digest username="admin", realm="Login to 7K02D8APAZ1C3F9", nonce="0011", uri="rtsp://1.2.3.4:554/cam/realmonitor?channel=1,subtype=0", response="6629fae49393a05397450978507c4ef1"`)
	require.Equal(t, Auth{
		Scheme:   "digest",
		Username: "admin",
		Realm:    "Login to 7K02D8APAZ1C3F9",
		URI:      "rtsp://1.2.3.4:554/cam/realmonitor?channel=1,subtype=0",
		Response: "6629fae49393a05397450978507c4ef1",
	}, digest)

	require.Equal(t, Auth{Scheme: "digest", Username: "root", Response: "ab"}, ParseAuthorization("digest username=root,response=ab"))
	require.Equal(t, Auth{Scheme: "basic"}, ParseAuthorization("Basic !!!"))
	require.Equal(t, Auth{Scheme: "bearer"}, ParseAuthorization("Bearer abc"))
}

func TestReplyOchiOptions(t *testing.T) {
	req, _, _, err := ReadRequest(bufio.NewReader(bytes.NewReader(ochiOptions)), 1024)
	require.NoError(t, err)
	code, data := fixedResponder().Reply(req)
	require.Equal(t, 200, code)
	require.Equal(t, "RTSP/1.0 200 OK\r\n"+
		"CSeq: 1\r\n"+
		"Date: Sat, 10 Oct 2026 21:44:20 GMT\r\n"+
		"Server: Rtsp Server/3.0\r\n"+
		"Public: OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, PAUSE, TEARDOWN, SET_PARAMETER, GET_PARAMETER\r\n"+
		"\r\n", string(data))
}

func TestReplyDescribeChallenge(t *testing.T) {
	code, data := fixedResponder().Reply(Request{Method: "DESCRIBE", Version: Version, Headers: map[string]string{"cseq": "2"}})
	require.Equal(t, 401, code)
	require.Equal(t, "RTSP/1.0 401 Unauthorized\r\n"+
		"CSeq: 2\r\n"+
		"Date: Sat, 10 Oct 2026 21:44:20 GMT\r\n"+
		"Server: Rtsp Server/3.0\r\n"+
		`WWW-Authenticate: Digest realm="Login to 7K02D8APAZ1C3F9", nonce="00112233445566778899aabbccddeeff"`+"\r\n"+
		`WWW-Authenticate: Basic realm="Login to 7K02D8APAZ1C3F9"`+"\r\n"+
		"\r\n", string(data))
}

func TestReplyCodes(t *testing.T) {
	r := fixedResponder()
	for _, tc := range []struct {
		method, version, cseq string
		want                  int
	}{
		{"SETUP", Version, "3", 401},
		{"ANNOUNCE", Version, "3", 401},
		{"RECORD", Version, "3", 401},
		{"PLAY", Version, "4", 454},
		{"PAUSE", Version, "4", 454},
		{"TEARDOWN", Version, "4", 454},
		{"GET_PARAMETER", Version, "4", 454},
		{"SET_PARAMETER", Version, "4", 454},
		{"REDIRECT", Version, "5", 501},
		{"FOO", Version, "5", 501},
		{"OPTIONS", "RTSP/2.0", "6", 505},
		{"OPTIONS", Version, "", 400},
		{"OPTIONS", Version, "abc", 400},
		{"OPTIONS", Version, "12345678901", 400},
	} {
		code, data := r.Reply(Request{Method: tc.method, Version: tc.version, Headers: map[string]string{"cseq": tc.cseq}})
		require.Equal(t, tc.want, code, tc.method)
		require.True(t, bytes.HasPrefix(data, []byte("RTSP/1.0 ")), tc.method)
		if tc.want == 400 {
			require.NotContains(t, string(data), "CSeq:")
		} else {
			require.Contains(t, string(data), "\r\nCSeq: "+tc.cseq+"\r\n")
		}
	}
}

func TestNewResponderRandomizes(t *testing.T) {
	a, b := NewResponder("r"), NewResponder("r")
	require.Len(t, a.Nonce, 32)
	require.NotEqual(t, a.Nonce, b.Nonce)
	require.Len(t, RandomSerial(), 15)
}
