package phpinfo

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// censysRequest is the request line and headers of Ochi event
// 6fd4f912-f244-4bec-824f-a9b75e3249bb (CensysInspect over TLS on tcp/41027).
const censysRequest = "GET /phpinfo.php HTTP/1.1\r\n" +
	"Host: 1.2.3.4:41027\r\n" +
	"User-Agent: Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)\r\n" +
	"Accept: */*\r\n" +
	"Accept-Encoding: gzip\r\n\r\n"

func fixedServer(t *testing.T) {
	t.Helper()
	prev := Server
	Server = Identity{
		Hostname:     "web01",
		Kernel:       "5.10.0-32-amd64",
		Build:        "#1 SMP Debian 5.10.223-1 (2024-08-10)",
		InvocationID: "4f0c2a9e7b13d5866a0e1f2b3c4d5e6f",
	}
	t.Cleanup(func() { Server = prev })
}

func censysInput() Input {
	return Input{
		Method:     "GET",
		RequestURI: "/phpinfo.php",
		Path:       "/phpinfo.php",
		Proto:      "HTTP/1.1",
		RawRequest: []byte(censysRequest),
		RemoteAddr: "167.94.146.51",
		RemotePort: "23082",
		ServerAddr: "10.0.0.5",
		ServerPort: 41027,
		HTTPS:      true,
		Now:        time.Date(2026, 10, 29, 19, 15, 4, 946000000, time.UTC),
	}
}

func split(t *testing.T, resp []byte) (string, string, []byte) {
	t.Helper()
	head, body, ok := bytes.Cut(resp, []byte("\r\n\r\n"))
	require.True(t, ok)
	status, headers, _ := strings.Cut(string(head), "\r\n")
	require.Contains(t, headers, "Content-Length: "+strconv.Itoa(len(body)))
	return status, headers, body
}

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		path, query, page string
	}{
		{"/phpinfo.php", "", "phpinfo.php"},
		{"/PHPINFO.PHP", "", "phpinfo.php"},
		{"/info.php", "", "info.php"},
		{"/public/phpinfo.php", "", "phpinfo.php"},
		{"/dashboard/phpinfo.php", "", "phpinfo.php"},
		{"/_profiler/phpinfo", "", "phpinfo"},
		{"/_profiler/phpinfo.php", "", "phpinfo.php"},
		{"/test.php", "", "test.php"},
		{"/i.php", "", "i.php"},
		{"/", "phpinfo=1", "index.php"},
		{"/index.php", "phpinfo=1", "index.php"},
		{"/l.php", "act=phpinfo", "l.php"},
	} {
		got := Match(tc.path, tc.query)
		require.NotNil(t, got, tc.path)
		require.Equal(t, tc.page, got.Page, tc.path)
	}
	for _, tc := range []struct{ path, query string }{
		{"/", ""},
		{"/index.php", ""},
		{"/index.php", "x=phpinfo"},
		{"/wp-admin/test.php", ""},
		{"/l.php", ""},
		{"/phpinfo.php.bak", ""},
		{"/..%2Fphpinfo.php", ""},
	} {
		require.Nil(t, Match(tc.path, tc.query), tc.path+"?"+tc.query)
	}
}

func TestRespondMatchesScanners(t *testing.T) {
	fixedServer(t)
	status, headers, body := split(t, Respond(censysInput()))
	require.Equal(t, "HTTP/1.1 200 OK", status)
	require.Contains(t, headers, "Date: Thu, 29 Oct 2026 19:15:04 GMT")
	require.Contains(t, headers, "Server: Apache/2.4.62 (Debian)")
	require.Contains(t, headers, "Content-Type: text/html; charset=UTF-8")

	// nuclei http/exposures/configs/phpinfo-files.yaml matchers and extractor
	page := string(body)
	require.Contains(t, page, "PHP Extension")
	require.Contains(t, page, "PHP Version")
	m := regexp.MustCompile(`>PHP Version <\/td><td class="v">([0-9.]+)`).FindStringSubmatch(page)
	require.Len(t, m, 2)
	require.Equal(t, "7.4.33", m[1])

	require.Contains(t, page, "<title>PHP 7.4.33 - phpinfo()</title>")
	require.Contains(t, page, "Linux web01 5.10.0-32-amd64 #1 SMP Debian 5.10.223-1 (2024-08-10) x86_64")
	require.Contains(t, page, "web01:41027")
	require.Contains(t, page, "4f0c2a9e7b13d5866a0e1f2b3c4d5e6f")
	require.Contains(t, page, `<td class="e">$_SERVER[&#39;REMOTE_ADDR&#39;]</td><td class="v">167.94.146.51</td>`)
	require.Contains(t, page, `<td class="e">$_SERVER[&#39;HTTPS&#39;]</td><td class="v">on</td>`)
	require.Contains(t, page, `<td class="e">$_SERVER[&#39;SERVER_NAME&#39;]</td><td class="v">1.2.3.4</td>`)
	require.Contains(t, page, `<td class="e">$_SERVER[&#39;REQUEST_TIME&#39;]</td><td class="v">1793301304</td>`)
	require.Contains(t, page, `<td class="e">User-Agent </td><td class="v">Mozilla/5.0 (compatible; CensysInspect/1.1; &#43;https://about.censys.io/) </td>`)
	require.Contains(t, page, "GET /phpinfo.php HTTP/1.1 ")
	for _, tell := range []string{"glutton", "honeypot", "mushorg"} {
		require.NotContains(t, strings.ToLower(page), tell)
	}
}

func TestRespondEscapesReflectedValues(t *testing.T) {
	fixedServer(t)
	in := censysInput()
	in.RequestURI = "/phpinfo.php?q=%3Cscript%3E"
	in.RawQuery = "q=<script>"
	in.RawRequest = []byte("GET /phpinfo.php HTTP/1.1\r\nHost: x\r\nX-Test: <b>\"hi\"</b>\r\nAuthorization: Basic Zm9vOmJhcg==\r\n\r\n")
	_, _, body := split(t, Respond(in))
	page := string(body)
	require.NotContains(t, page, "<b>")
	require.NotContains(t, page, "<script>")
	require.Contains(t, page, "HTTP_X_TEST")
	require.Contains(t, page, "&lt;b&gt;")
	// Apache keeps Authorization out of the environment
	require.NotContains(t, page, "HTTP_AUTHORIZATION")
	require.Contains(t, page, "$_GET[&#39;q&#39;]")
}

func TestRespondHead(t *testing.T) {
	fixedServer(t)
	in := censysInput()
	in.Method = "HEAD"
	head := Respond(in)
	// headers only: Content-Length is the page length, no body follows
	require.True(t, bytes.HasSuffix(head, []byte("\r\n\r\n")))
	require.Equal(t, 1, bytes.Count(head, []byte("\r\n\r\n")))
	require.NotContains(t, string(head), "Content-Length: 0\r\n")
}

func TestHeaderLinesCaps(t *testing.T) {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < maxHeaders+10; i++ {
		b.WriteString("X-H" + strconv.Itoa(i) + ": " + strings.Repeat("A", maxHeaderValue+50) + "\r\n")
	}
	b.WriteString("\r\nbody: not a header")
	rows := headerLines([]byte(b.String()))
	require.Len(t, rows, maxHeaders)
	require.Equal(t, "X-H0", rows[0].Key)
	require.Len(t, rows[0].Value, maxHeaderValue)
}

func TestNewIdentity(t *testing.T) {
	id := NewIdentity()
	require.NotEmpty(t, id.Hostname)
	require.Contains(t, id.Kernel, "-amd64")
	require.Len(t, id.InvocationID, 32)
}
