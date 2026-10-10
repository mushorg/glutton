package icap

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// read frame 1 of https://ochi.mushmush.org/events/9b3f8947-17bb-4c7f-af45-6ca88717dc1e (tcp/1344)
var optionsProbe = []byte("OPTIONS icap://1.2.3.4:1344/ ICAP/1.0\r\nHost: 1.2.3.4:1344\r\n\r\n")

const httpReq = "POST /upload HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 11\r\n\r\n"

// reqmod builds a synthetic REQMOD in the RFC 3507 §4.8.3 shape.
func reqmod(extra, body string) string {
	return "REQMOD icap://icap.example.org/avscan ICAP/1.0\r\n" +
		"Host: icap.example.org\r\n" + extra +
		fmt.Sprintf("Encapsulated: req-hdr=0, req-body=%d\r\n\r\n", len(httpReq)) +
		httpReq + body
}

var persona = Persona{Server: "C-ICAP/0.5.10", Service: "C-ICAP/0.5.10 server - Echo demo service", ISTag: "CI0001-XXXXXXXXX"}

var date = time.Date(2026, 10, 10, 21, 38, 45, 0, time.UTC)

func read(t *testing.T, data string, maxBody int) (Request, []byte, bool, error) {
	t.Helper()
	return ReadRequest(bufio.NewReader(strings.NewReader(data)), maxBody)
}

func TestReadRequestOptionsProbe(t *testing.T) {
	req, raw, truncated, err := read(t, string(optionsProbe), 1024)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, optionsProbe, raw)
	require.Equal(t, MethodOptions, req.Method)
	require.Equal(t, "icap://1.2.3.4:1344/", req.URI)
	require.Equal(t, "/", req.Service)
	require.Equal(t, "ICAP/1.0", req.Version)
	require.Equal(t, "1.2.3.4:1344", req.Header("host"))
	require.False(t, req.HasBody())
	require.Equal(t, -1, req.Preview)
	require.True(t, LooksLikeICAP(optionsProbe))
}

func TestReadRequestPreviewThenContinue(t *testing.T) {
	wire := reqmod("Allow: 204\r\nPreview: 4\r\n", "4\r\nhell\r\n0\r\n\r\n")
	r := bufio.NewReader(strings.NewReader(wire + "7\r\no world\r\n0\r\n\r\n"))

	req, raw, truncated, err := ReadRequest(r, 1024)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, wire, string(raw))
	require.Equal(t, "/avscan", req.Service)
	require.Equal(t, "req-body", req.BodyType)
	require.Equal(t, httpReq, string(req.ReqHdr))
	require.Equal(t, "POST /upload HTTP/1.1", req.HTTPRequestLine())
	require.Equal(t, 4, req.Preview)
	require.Equal(t, "hell", string(req.Body))
	require.True(t, req.NeedsContinue())
	require.True(t, req.Allows204())

	body, raw, truncated, err := ReadChunked(r, 1024)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, "o world", string(body))
	require.Equal(t, "7\r\no world\r\n0\r\n\r\n", string(raw))
}

func TestReadRequestPreviewIEOF(t *testing.T) {
	req, _, _, err := read(t, reqmod("Preview: 1024\r\n", "b\r\nhello world\r\n0; ieof\r\n\r\n"), 1024)
	require.NoError(t, err)
	require.True(t, req.IEOF)
	require.False(t, req.NeedsContinue())
	require.False(t, req.Allows204())
	require.Equal(t, "hello world", string(req.Body))
}

func TestReadRequestRespmodHeaders(t *testing.T) {
	reqHdr := "GET /origin-resource HTTP/1.1\r\nHost: www.origin-server.com\r\n\r\n"
	resHdr := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
	wire := "RESPMOD icap://icap.example.org/satisf ICAP/1.0\r\n" +
		fmt.Sprintf("Encapsulated: req-hdr=0, res-hdr=%d, res-body=%d\r\n\r\n", len(reqHdr), len(reqHdr)+len(resHdr)) +
		reqHdr + resHdr + "3\r\nabc\r\n0\r\n\r\n"
	req, _, _, err := read(t, wire, 1024)
	require.NoError(t, err)
	require.Equal(t, reqHdr, string(req.ReqHdr))
	require.Equal(t, resHdr, string(req.ResHdr))
	require.Equal(t, "HTTP/1.1 200 OK", req.HTTPStatusLine())
	require.Equal(t, "abc", string(req.Body))
}

func TestReadRequestBodyTruncated(t *testing.T) {
	wire := reqmod("", "b\r\nhello world\r\n0\r\n\r\n")
	r := bufio.NewReader(strings.NewReader(wire + "OPTIONS icap://x/ ICAP/1.0\r\n\r\n"))
	req, raw, truncated, err := ReadRequest(r, 5)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Equal(t, "hello", string(req.Body))
	require.NotContains(t, string(raw), "world")

	// the stream stays in sync for the next request
	next, _, _, err := ReadRequest(r, 5)
	require.NoError(t, err)
	require.Equal(t, MethodOptions, next.Method)
}

func TestReadRequestBodyTooLarge(t *testing.T) {
	_, _, truncated, err := read(t, reqmod("", fmt.Sprintf("%x\r\n", maxDiscard+10)), 4)
	require.ErrorIs(t, err, ErrBodyTooLarge)
	require.True(t, truncated)
}

func TestReadRequestErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		wire string
		err  error
	}{
		"empty":            {"", io.EOF},
		"http":             {"GET / HTTP/1.1\r\n\r\n", ErrMalformed},
		"header no colon":  {"OPTIONS icap://x/ ICAP/1.0\r\nbogus\r\n\r\n", ErrMalformed},
		"bad preview":      {"OPTIONS icap://x/ ICAP/1.0\r\nPreview: -1\r\n\r\n", ErrMalformed},
		"bad encapsulated": {"REQMOD icap://x/ ICAP/1.0\r\nEncapsulated: req-hdr=0\r\n\r\n", ErrMalformed},
		"bad chunk size":   {"REQMOD icap://x/ ICAP/1.0\r\nEncapsulated: req-body=0\r\n\r\nzz\r\n", ErrMalformed},
		"missing crlf":     {"REQMOD icap://x/ ICAP/1.0\r\nEncapsulated: req-body=0\r\n\r\n1\r\naX\r\n", ErrMalformed},
		"cut in headers":   {"OPTIONS icap://x/ ICAP/1.0\r\nHost: x\r\n", io.ErrUnexpectedEOF},
		"cut in body":      {"REQMOD icap://x/ ICAP/1.0\r\nEncapsulated: req-body=0\r\n\r\n5\r\nab", io.ErrUnexpectedEOF},
		"cut in http hdrs": {"REQMOD icap://x/ ICAP/1.0\r\nEncapsulated: req-hdr=0, null-body=50\r\n\r\nGET /", io.ErrUnexpectedEOF},
		"long line":        {"OPTIONS icap://" + strings.Repeat("a", 5000), ErrLineTooLong},
	} {
		t.Run(name, func(t *testing.T) {
			_, raw, _, err := read(t, tc.wire, 1024)
			require.ErrorIs(t, err, tc.err)
			if tc.wire != "" {
				require.NotEmpty(t, raw)
			}
		})
	}
}

func TestParseEncapsulated(t *testing.T) {
	s, err := ParseEncapsulated("req-hdr=0, res-hdr=137, res-body=296")
	require.NoError(t, err)
	require.Equal(t, []Section{{"req-hdr", 0}, {"res-hdr", 137}, {"res-body", 296}}, s)

	for _, bad := range []string{"", "req-hdr=0", "req-body=0, req-hdr=5", "req-hdr=10, req-body=5", "foo=0", "null-body=x", "null-body=999999"} {
		_, err := ParseEncapsulated(bad)
		require.ErrorIs(t, err, ErrMalformed, bad)
	}
}

func TestServicePath(t *testing.T) {
	require.Equal(t, "/", servicePath("icap://1.2.3.4:1344"))
	require.Equal(t, "/avscan", servicePath("icap://host/avscan?mode=x"))
	require.Equal(t, "/echo", servicePath("/echo"))
	require.Equal(t, "", servicePath("*"))
}

func TestBuildOptions(t *testing.T) {
	require.Equal(t, "ICAP/1.0 200 OK\r\n"+
		"Methods: RESPMOD, REQMOD\r\n"+
		"Service: C-ICAP/0.5.10 server - Echo demo service\r\n"+
		"ISTag: \"CI0001-XXXXXXXXX\"\r\n"+
		"Transfer-Preview: *\r\n"+
		"Options-TTL: 3600\r\n"+
		"Date: Sat, 10 Oct 2026 21:38:45 GMT\r\n"+
		"Preview: 1024\r\n"+
		"Allow: 204\r\n"+
		"Max-Connections: 600\r\n"+
		"X-Include: X-Authenticated-User, X-Authenticated-Groups\r\n"+
		"Encapsulated: null-body=0\r\n\r\n", string(BuildOptions(persona, date)))
}

func TestBuildStatus(t *testing.T) {
	require.Equal(t, "ICAP/1.0 204 Unmodified\r\n"+
		"Server: C-ICAP/0.5.10\r\n"+
		"Connection: keep-alive\r\n"+
		"ISTag: \"CI0001-XXXXXXXXX\"\r\n"+
		"Date: Sat, 10 Oct 2026 21:38:45 GMT\r\n"+
		"Encapsulated: null-body=0\r\n\r\n", string(BuildStatus(204, persona, date)))
	require.Equal(t, "ICAP/1.0 100 Continue\r\n\r\n", string(BuildContinue()))
}

func TestBuildEcho(t *testing.T) {
	req, _, _, err := read(t, reqmod("", "b\r\nhello world\r\n0\r\n\r\n"), 1024)
	require.NoError(t, err)
	echo := BuildEcho(req, persona, date)
	head, rest, ok := bytes.Cut(echo, []byte("\r\n\r\n"))
	require.True(t, ok)
	require.Contains(t, string(head), fmt.Sprintf("Encapsulated: req-hdr=0, req-body=%d", len(httpReq)))
	require.Equal(t, httpReq+"b\r\nhello world\r\n0\r\n\r\n", string(rest))

	// a RESPMOD without encapsulated data echoes null-body
	req.Method = MethodRespmod
	req.ResHdr = nil
	req.BodyType = "null-body"
	require.True(t, strings.HasSuffix(string(BuildEcho(req, persona, date)), "Encapsulated: null-body=0\r\n\r\n"))
}
