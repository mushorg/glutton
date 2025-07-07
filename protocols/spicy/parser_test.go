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

	httpRequest := "GET /test HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"
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

	method := result.Fields["method"]
	require.Equal(t, "GET", method)

	uri := result.Fields["uri"]
	require.Equal(t, "/test", uri)

	version := result.Fields["version.number"]
	require.Equal(t, "1.1", version)
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
