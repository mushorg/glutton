package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/mocks"
	"github.com/mushorg/glutton/protocols/spicy"
	"github.com/mushorg/glutton/rules"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockConn struct {
	net.Conn
	readBuf    *bytes.Buffer
	writeBuf   *bytes.Buffer
	remoteAddr net.Addr
	closed     bool
}

func newMockConn(data string) *mockConn {
	return &mockConn{
		readBuf:    bytes.NewBufferString(data),
		writeBuf:   &bytes.Buffer{},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
	}
}

func (m *mockConn) Read(b []byte) (n int, err error)  { return m.readBuf.Read(b) }
func (m *mockConn) Write(b []byte) (n int, err error) { return m.writeBuf.Write(b) }
func (m *mockConn) Close() error                      { m.closed = true; return nil }
func (m *mockConn) RemoteAddr() net.Addr              { return m.remoteAddr }
func (m *mockConn) Written() string                   { return m.writeBuf.String() }

func createMockLogger() *mocks.MockLogger {
	logger := &mocks.MockLogger{}

	logger.EXPECT().Info(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything).Return().Maybe()
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Error(mock.Anything).Return().Maybe()
	logger.EXPECT().Debug(mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Debug(mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Debug(mock.Anything).Return().Maybe()

	return logger
}

// initialize Spicy once for all tests
var spicyInitOnce sync.Once

func ensureSpicyInitialized() {
	spicyInitOnce.Do(func() {
		logger := createMockLogger()
		spicy.Initialize(logger)
	})
}

func buildHTTPRequest(method, target, body string, headers ...string) string {
	request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.com\r\n", method, target)
	for _, header := range headers {
		request += header + "\r\n"
	}
	if body != "" {
		request += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	}
	return request + "\r\n" + body
}

func runHTTPHandler(t *testing.T, request string) (*mockConn, []parsedHTTP) {
	t.Helper()
	return runHTTPHandlerOnPort(t, request, 80)
}

func runHTTPHandlerOnPort(t *testing.T, request string, port uint16) (*mockConn, []parsedHTTP) {
	t.Helper()
	ensureSpicyInitialized()

	conn := newMockConn(request)
	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	honeypot.EXPECT().UpdateConnectionTimeout(mock.Anything, mock.Anything).Return(nil)
	var gotDecoded interface{}
	honeypot.EXPECT().ProduceTCP("http", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ string, _ net.Conn, _ connection.Metadata, _ []byte, decoded interface{}) {
			gotDecoded = decoded
		}).
		Return(nil)

	md := connection.Metadata{
		TargetPort: port,
		Rule:       &rules.Rule{Target: "http"},
	}

	err := HandleHTTP(context.Background(), conn, md, logger, honeypot)
	require.NoError(t, err)
	require.True(t, conn.closed)

	logger.AssertExpectations(t)
	honeypot.AssertExpectations(t)

	events, ok := gotDecoded.([]parsedHTTP)
	require.True(t, ok)
	return conn, events
}

func TestHandleHTTPBasicGET(t *testing.T) {
	conn, events := runHTTPHandler(t, buildHTTPRequest("GET", "/test", ""))

	require.Contains(t, conn.Written(), "HTTP/1.1 200 OK")
	require.Len(t, events, 2)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "GET", events[0].Command)
	require.Equal(t, "/test", events[0].Path)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "200", events[1].Status)
}

func TestHandleHTTPResponseBranches(t *testing.T) {
	ethereumBody := `{"jsonrpc":"2.0","method":"eth_blockNumber","id":1}`

	tests := []struct {
		name     string
		request  string
		contains string
	}{
		{
			name:     "Default",
			request:  buildHTTPRequest("GET", "/test", ""),
			contains: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name:     "Wallet",
			request:  buildHTTPRequest("GET", "/wallet", ""),
			contains: `[[""]]`,
		},
		{
			name:     "Docker",
			request:  buildHTTPRequest("GET", "/v1.16/version", ""),
			contains: `"ApiVersion":"1.41"`,
		},
		{
			name:     "YARN",
			request:  buildHTTPRequest("POST", "/ws/v1/cluster/apps/new-application", `{}`),
			contains: `"application-id":"application_1527144634877_20465"`,
		},
		{
			name:     "Ethereum",
			request:  buildHTTPRequest("POST", "/", ethereumBody),
			contains: `"result":"0x2ecd9e"`,
		},
		{
			name:     "Citrix",
			request:  buildHTTPRequest("GET", "/vpn/../vpns/cfg/smb.conf", ""),
			contains: "[global]",
		},
		{
			name:     "CitrixLogin",
			request:  buildHTTPRequest("GET", "/vpn/index.html", ""),
			contains: "<title>NetScaler Gateway</title>",
		},
		{
			name:     "CitrixTemplateWrite",
			request:  buildHTTPRequest("POST", "/vpn/../vpns/portal/scripts/newbm.pl", "url=http://example.com&title=%5B%25+7*7+%25%5D&desc=d&UI_inuse=a"),
			contains: "parent.window.ns_reload",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn, events := runHTTPHandler(t, test.request)
			require.Contains(t, conn.Written(), test.contains)
			require.GreaterOrEqual(t, len(events), 2)
			require.Equal(t, "write", events[len(events)-1].Direction)
			require.Equal(t, "200", events[len(events)-1].Status)
		})
	}
}

func TestHandleHTTPUsesParsedQuery(t *testing.T) {
	_, events := runHTTPHandler(t, buildHTTPRequest("GET", "/test/path?x=1&y=two", ""))

	require.Equal(t, "/test/path", events[0].Path)
	require.Equal(t, "x=1&y=two", events[0].Query)
	require.Equal(t, url.Values{"x": {"1"}, "y": {"two"}}, events[0].Parameters)
}

func TestHandleHTTPWithBody(t *testing.T) {
	ensureSpicyInitialized()

	body := `{"test":true}`
	request := buildHTTPRequest("POST", "/api", body)
	conn := newMockConn(request)
	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	md := connection.Metadata{
		TargetPort: 80,
		Rule:       &rules.Rule{Target: "http"},
	}

	var gotPayload []byte
	var gotDecoded interface{}
	honeypot.EXPECT().UpdateConnectionTimeout(mock.Anything, mock.Anything).Return(nil)
	honeypot.EXPECT().ProduceTCP("http", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ string, _ net.Conn, _ connection.Metadata, payload []byte, decoded interface{}) {
			gotPayload = append([]byte(nil), payload...)
			gotDecoded = decoded
		}).
		Return(nil)

	err := HandleHTTP(context.Background(), conn, md, logger, honeypot)
	require.NoError(t, err)
	require.True(t, conn.closed)
	require.Equal(t, []byte(request), gotPayload)

	events, ok := gotDecoded.([]parsedHTTP)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, "POST", events[0].Command)
	require.Equal(t, "/api", events[0].Path)
	require.Equal(t, []byte(request), events[0].Payload)
	require.Equal(t, "200", events[1].Status)

	logger.AssertExpectations(t)
	honeypot.AssertExpectations(t)
}

func TestHandleHTTPKeepAlive(t *testing.T) {
	req1 := buildHTTPRequest("GET", "/one", "")
	req2 := buildHTTPRequest("GET", "/two", "")
	conn, events := runHTTPHandler(t, req1+req2)

	require.Len(t, events, 4)
	require.Equal(t, "/one", events[0].Path)
	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, "/two", events[2].Path)
	require.Equal(t, "write", events[3].Direction)
	require.Equal(t, 2, bytes.Count([]byte(conn.Written()), []byte("HTTP/1.1 200 OK")))
}

func TestHandleHTTPMalformedRequest(t *testing.T) {
	ensureSpicyInitialized()
	t.Chdir(t.TempDir())

	malformedRequest := "GET /path\r\nHost: 203.0.113.50\r\n\r\n"
	conn := newMockConn(malformedRequest)

	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	honeypot.EXPECT().UpdateConnectionTimeout(mock.Anything, mock.Anything).Return(nil)
	var gotHandler string
	var gotPayload []byte
	honeypot.EXPECT().ProduceTCP(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(handler string, _ net.Conn, _ connection.Metadata, payload []byte, _ interface{}) {
			gotHandler = handler
			gotPayload = append([]byte(nil), payload...)
		}).
		Return(nil)

	md := connection.Metadata{TargetPort: 80}
	err := HandleHTTP(context.Background(), conn, md, logger, honeypot)
	require.NoError(t, err)
	require.True(t, conn.closed)
	require.Equal(t, "tcp", gotHandler)
	require.Equal(t, []byte(malformedRequest), gotPayload)
	require.Contains(t, conn.Written(), "HTTP/1.1 200 OK")

	logger.AssertExpectations(t)
	honeypot.AssertExpectations(t)
}

func TestRequestPathAndQueryStripsHost(t *testing.T) {
	path, query := requestPathAndQuery("http://203.0.113.50/wallet?x=1", "http://203.0.113.50/wallet", "x=1")
	require.Equal(t, "/wallet", path)
	require.Equal(t, "x=1", query)
	require.NotContains(t, path, "203.0.113.50")
}

func TestHandleHTTPDoesNotProduceSensorAddress(t *testing.T) {
	ensureSpicyInitialized()

	sensorIP := "203.0.113.50"
	request := fmt.Sprintf("GET http://%s/test/path?x=1 HTTP/1.1\r\nHost: %s\r\nX-Forwarded-For: %s\r\n\r\n", sensorIP, sensorIP, sensorIP)

	conn := newMockConn(request)
	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	md := connection.Metadata{
		TargetPort: 80,
		Rule:       &rules.Rule{Target: "http"},
	}

	var gotDecoded interface{}
	honeypot.EXPECT().UpdateConnectionTimeout(mock.Anything, mock.Anything).Return(nil)
	honeypot.EXPECT().ProduceTCP("http", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ string, _ net.Conn, _ connection.Metadata, _ []byte, decoded interface{}) {
			gotDecoded = decoded
		}).
		Return(nil)

	err := HandleHTTP(context.Background(), conn, md, logger, honeypot)
	require.NoError(t, err)

	events, ok := gotDecoded.([]parsedHTTP)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(events), 1)
	require.Equal(t, "GET", events[0].Command)
	require.Equal(t, "/test/path", events[0].Path)
	require.Equal(t, "x=1", events[0].Query)
	require.NotContains(t, events[0].Path, sensorIP)
	require.NotContains(t, events[0].Query, sensorIP)
	require.NotContains(t, events[0].Command, sensorIP)

	logger.AssertExpectations(t)
	honeypot.AssertExpectations(t)
}

func TestHandleHTTPEmptyRequest(t *testing.T) {
	ensureSpicyInitialized()

	conn := newMockConn("")
	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	honeypot.EXPECT().UpdateConnectionTimeout(mock.Anything, mock.Anything).Return(nil)
	// empty connection: no frames, so no ProduceTCP

	md := connection.Metadata{TargetPort: 80}
	ctx := context.Background()

	err := HandleHTTP(ctx, conn, md, logger, honeypot)
	require.NoError(t, err)
	require.True(t, conn.closed)

	logger.AssertExpectations(t)
	honeypot.AssertExpectations(t)
}

func TestHandleHTTPSingleProduce(t *testing.T) {
	req1 := buildHTTPRequest("GET", "/a", "")
	req2 := buildHTTPRequest("GET", "/b", "")
	ensureSpicyInitialized()

	conn := newMockConn(req1 + req2)
	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	honeypot.EXPECT().UpdateConnectionTimeout(mock.Anything, mock.Anything).Return(nil)
	honeypot.EXPECT().ProduceTCP("http", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Once()

	md := connection.Metadata{TargetPort: 80, Rule: &rules.Rule{Target: "http"}}
	require.NoError(t, HandleHTTP(context.Background(), conn, md, logger, honeypot))
	honeypot.AssertExpectations(t)
}

// seleniumGreedBody is shaped like a SeleniumGreed new-session request with a
// harmless payload (synthetic, not captured).
const seleniumGreedBody = `{"capabilities":{"alwaysMatch":{"browserName":"chrome","goog:chromeOptions":` +
	`{"binary":"/usr/bin/python3","args":["-cimport base64;exec(base64.b64decode(b'aW1wb3J0IG9z'))"]}}}}`

func TestHandleHTTPSeleniumGrid(t *testing.T) {
	request := buildHTTPRequest("GET", "/status", "") +
		buildHTTPRequest("POST", "/wd/hub/session", seleniumGreedBody, "Content-Type: application/json; charset=utf-8")
	conn, events := runHTTPHandlerOnPort(t, request, 4444)

	require.Contains(t, conn.Written(), "Selenium Grid ready.")
	require.Len(t, events, 4)
	require.Equal(t, "/status", events[0].Path)
	require.Empty(t, events[0].Binary)
	require.Equal(t, "200", events[1].Status)

	require.Equal(t, "read", events[2].Direction)
	require.Equal(t, "POST", events[2].Command)
	require.Equal(t, "/wd/hub/session", events[2].Path)
	require.Equal(t, "chrome", events[2].Browser)
	require.Equal(t, "/usr/bin/python3", events[2].Binary)
	require.Equal(t, []string{"-cimport base64;exec(base64.b64decode(b'aW1wb3J0IG9z'))"}, events[2].Args)
	require.False(t, events[2].Truncated)

	require.Equal(t, "write", events[3].Direction)
	require.Equal(t, "500", events[3].Status)
	require.Contains(t, string(events[3].Payload), `"error": "session not created"`)
}

func TestHandleHTTPSeleniumOnlyOnGridPortOrHubPath(t *testing.T) {
	// /wd/hub is the Grid on any port
	conn, events := runHTTPHandler(t, buildHTTPRequest("GET", "/wd/hub/status", ""))
	require.Contains(t, conn.Written(), "Selenium Grid ready.")
	require.Equal(t, "200", events[1].Status)

	// a bare /status off the Grid port keeps the generic reply, and a
	// session-shaped POST there records no Selenium fields
	conn, events = runHTTPHandler(t, buildHTTPRequest("POST", "/session", seleniumGreedBody))
	require.NotContains(t, conn.Written(), "session not created")
	require.Empty(t, events[0].Binary)
}
