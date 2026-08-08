package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net"
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

	// generic expectations that handle all variations
	logger.EXPECT().Info(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything).Return().Maybe()
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Error(mock.Anything).Return().Maybe()

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

func runHTTPHandler(t *testing.T, request string) *mockConn {
	t.Helper()
	ensureSpicyInitialized()

	conn := newMockConn(request)
	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	honeypot.EXPECT().ProduceTCP("http", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	md := connection.Metadata{
		TargetPort: 80,
		Rule:       &rules.Rule{Target: "http"},
	}

	err := HandleHTTP(context.Background(), conn, md, logger, honeypot)
	require.NoError(t, err)
	require.True(t, conn.closed)

	logger.AssertExpectations(t)
	honeypot.AssertExpectations(t)

	return conn
}

func TestHandleHTTPBasicGET(t *testing.T) {
	conn := runHTTPHandler(t, buildHTTPRequest("GET", "/test", ""))

	require.Contains(t, conn.Written(), "HTTP/1.1 200 OK")
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
			contains: "HTTP/1.1 200 OK\r\n\r\n",
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
			request:  buildHTTPRequest("GET", "/vpn/index.html", ""),
			contains: "[global]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Contains(t, runHTTPHandler(t, test.request).Written(), test.contains)
		})
	}
}

func TestHandleHTTPUsesParsedQuery(t *testing.T) {
	conn := runHTTPHandler(t, buildHTTPRequest("GET", "/test/path?x=1&y=two", ""))

	require.Contains(t, conn.Written(), "HTTP/1.1 200 OK")
}

func TestHandleHTTPWithBody(t *testing.T) {
	conn := runHTTPHandler(t, buildHTTPRequest("POST", "/api", `{"test":true}`))

	require.True(t, conn.closed)
}

func TestHandleHTTPMalformedRequest(t *testing.T) {
	ensureSpicyInitialized()

	malformedRequest := "GET /path\r\nHost: test\r\n\r\n"
	conn := newMockConn(malformedRequest)

	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	honeypot.EXPECT().ProduceTCP("spicy-http-failed", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	md := connection.Metadata{TargetPort: 80}
	ctx := context.Background()

	err := HandleHTTP(ctx, conn, md, logger, honeypot)
	require.Error(t, err)
	require.True(t, conn.closed)

	logger.AssertExpectations(t)
	honeypot.AssertExpectations(t)
}

func TestHandleHTTPEmptyRequest(t *testing.T) {
	ensureSpicyInitialized()

	conn := newMockConn("")
	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}

	md := connection.Metadata{TargetPort: 80}
	ctx := context.Background()

	err := HandleHTTP(ctx, conn, md, logger, honeypot)
	require.Error(t, err) // empty request should error (EOF when trying to read)
	require.True(t, conn.closed)
}
