package spicy

import (
	"bufio"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadHTTPMessageCapsHeaders(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nX-Long: " + strings.Repeat("a", MaxHTTPHeader) + "\r\n\r\n"))
	raw, err := ReadHTTPMessage(r, MaxHTTPBody)
	require.ErrorIs(t, err, errHTTPHeaderTooLarge)
	require.Len(t, raw, MaxHTTPHeader)
}

func TestReadHTTPMessageWithinHeaderCap(t *testing.T) {
	req := "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"
	raw, err := ReadHTTPMessage(bufio.NewReader(strings.NewReader(req)), MaxHTTPBody)
	require.NoError(t, err)
	require.Equal(t, req, string(raw))
}
