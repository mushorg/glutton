package spicy

import (
	"sync"
	"testing"

	"github.com/mushorg/glutton/protocols/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func createMockLogger() *mocks.MockLogger {
	logger := &mocks.MockLogger{}
	logger.EXPECT().Info(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Info(mock.Anything).Return().Maybe()
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return().Maybe()
	logger.EXPECT().Error(mock.Anything).Return().Maybe()
	return logger
}

var spicyInitOnce sync.Once
var spicyInitErr error

func ensureSpicyInitialized() {
	spicyInitOnce.Do(func() {
		logger := createMockLogger()
		spicyInitErr = Initialize(logger)
	})
}

func TestInitialize(t *testing.T) {
	ensureSpicyInitialized()

	logger := createMockLogger()

	err1 := Initialize(logger)
	err2 := Initialize(logger)

	if spicyInitErr != nil {
		require.Error(t, err1)
		require.Error(t, err2)
		t.Logf("Initialize failed (expected if Spicy not available): %v", err1)
	} else {
		require.NoError(t, err1)
		require.NoError(t, err2)
	}

	logger.AssertExpectations(t)
}

func TestParseHTTPRequest(t *testing.T) {
	ensureSpicyInitialized()

	if spicyInitErr != nil {
		t.Skipf("Skipping test as Spicy initialization failed: %v", spicyInitErr)
	}

	httpRequest := "POST /test/path?x=1&y=two HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: glutton-test\r\nContent-Type: application/json\r\nContent-Length: 4\r\n\r\ntest"
	result, err := Parse("http", []byte(httpRequest))

	if err != nil {
		if err.Error() == "no Spicy parser registered for \"http\"" {
			t.Skip("HTTP parser not available in this build")
			return
		}
		require.NoError(t, err, "Unexpected parsing error")
	}

	require.NotNil(t, result)
	require.Equal(t, "http", result.Protocol)
	require.NotNil(t, result.Fields)
	require.NoError(t, result.Error)

	require.Equal(t, "POST", result.Fields["method"])
	require.Equal(t, "/test/path?x=1&y=two", result.Fields["uri.raw"])
	require.Equal(t, "/test/path", result.Fields["uri.path"])
	require.Equal(t, "x=1&y=two", result.Fields["uri.query"])
	require.Equal(t, "1.1", result.Fields["version.number"])
	require.Equal(t, "Host", result.Fields["headers[0].name"])
	require.Equal(t, "example.com:8080", result.Fields["headers[0].value"])
	require.Equal(t, "test", result.Fields["body.content"])
	require.NotContains(t, result.Fields, "header.host")
	require.NotContains(t, result.Fields, "header.user_agent")
	require.NotContains(t, result.Fields, "header.content_type")
	require.NotContains(t, result.Fields, "header.content_length")
	require.NotContains(t, result.Fields, "host")
	require.NotContains(t, result.Fields, "port_")
}

func TestParseHTTPRequestAbsoluteTarget(t *testing.T) {
	ensureSpicyInitialized()

	if spicyInitErr != nil {
		t.Skipf("Skipping test as Spicy initialization failed: %v", spicyInitErr)
	}

	httpRequest := "GET http://example.com/test/path?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
	result, err := Parse("http", []byte(httpRequest))

	if err != nil {
		if err.Error() == "no Spicy parser registered for \"http\"" {
			t.Skip("HTTP parser not available in this build")
			return
		}
		require.NoError(t, err, "Unexpected parsing error")
	}

	require.NotNil(t, result)
	require.Equal(t, "http://example.com/test/path?x=1", result.Fields["uri.raw"])
	require.Equal(t, "http://example.com/test/path", result.Fields["uri.path"])
	require.Equal(t, "x=1", result.Fields["uri.query"])
}

func TestParseUnknownProtocol(t *testing.T) {
	ensureSpicyInitialized()

	if spicyInitErr != nil {
		t.Skipf("Skipping test as Spicy initialization failed: %v", spicyInitErr)
	}

	result, err := Parse("unknown-protocol", []byte("test data"))

	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "no Spicy parser registered")
}

func TestParseEmptyData(t *testing.T) {
	ensureSpicyInitialized()

	if spicyInitErr != nil {
		t.Skipf("Skipping test as Spicy initialization failed: %v", spicyInitErr)
	}

	result, err := Parse("http", []byte{})

	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "input data is empty")
}

func TestParseNilData(t *testing.T) {
	ensureSpicyInitialized()

	if spicyInitErr != nil {
		t.Skipf("Skipping test as Spicy initialization failed: %v", spicyInitErr)
	}

	result, err := Parse("http", nil)

	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "input data is empty")
}

func TestCleanup(t *testing.T) {
	err := Cleanup()
	require.NoError(t, err)
}
