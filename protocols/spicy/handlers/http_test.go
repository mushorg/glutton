package handlers

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/mocks"
	"github.com/mushorg/glutton/protocols/spicy"
	"github.com/mushorg/glutton/rules"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockConn struct {
	readBuf    *bytes.Buffer
	writeBuf   *bytes.Buffer
	remoteAddr net.Addr
	localAddr  net.Addr
	closed     bool
}

func newMockConn(data string) *mockConn {
	return &mockConn{
		readBuf:    bytes.NewBufferString(data),
		writeBuf:   &bytes.Buffer{},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
		localAddr:  &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80},
	}
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return m.readBuf.Read(b) }
func (m *mockConn) Write(b []byte) (n int, err error)  { return m.writeBuf.Write(b) }
func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockConn) Written() string                    { return m.writeBuf.String() }

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

func TestHandleHTTPBasicGET(t *testing.T) {
	ensureSpicyInitialized()

	httpRequest := "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
	conn := newMockConn(httpRequest)

	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	honeypot.EXPECT().ProduceTCP(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	md := connection.Metadata{
		TargetPort: 80,
		Rule:       &rules.Rule{Target: "http"},
	}

	ctx := context.Background()
	err := HandleHTTP(ctx, conn, md, logger, honeypot)

	require.NoError(t, err)
	require.True(t, conn.closed)

	response := conn.Written()
	require.Contains(t, response, "HTTP/1.1 200 OK")

	logger.AssertExpectations(t)
	honeypot.AssertExpectations(t)
}

func TestHandleHTTPWithBody(t *testing.T) {
	ensureSpicyInitialized()

	httpRequest := "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\n{\"test\":true}"
	conn := newMockConn(httpRequest)

	logger := createMockLogger()
	honeypot := &mocks.MockHoneypot{}
	honeypot.EXPECT().ProduceTCP(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	md := connection.Metadata{TargetPort: 80}
	ctx := context.Background()

	err := HandleHTTP(ctx, conn, md, logger, honeypot)
	require.NoError(t, err)
	require.True(t, conn.closed)

	logger.AssertExpectations(t)
	honeypot.AssertExpectations(t)
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
