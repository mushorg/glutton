package protocols

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatRequest(t *testing.T) {
	mockReq, err := http.NewRequest("GET", "http://example.com", nil)
	require.NoError(t, err)
	require.Equal(t, "GET http://example.com HTTP/1.1\nHost: example.com", formatRequest(mockReq))
}
