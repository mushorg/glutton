package protocols

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPeek(t *testing.T) {
	conn, close := testConn(t)
	defer close()
	snip, _, err := Peek(conn, 1)
	var netErr net.Error
	ok := errors.As(err, &netErr)
	require.True(t, ok)
	require.True(t, netErr.Timeout())
	require.Empty(t, snip)
}

func TestPeekLine(t *testing.T) {
	for _, tc := range []struct {
		name    string
		writes  []string
		max     int
		want    string
		timeout bool
	}{
		{"line in one segment", []string{"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"}, 256, "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n", false},
		{"line split across segments", []string{"OPTI", "ONS * RTSP/1.0\r\n"}, 256, "OPTIONS * RTSP/1.0\r\n", false},
		{"cap without newline", []string{"DESCRIBE rtsp://host/long"}, 8, "DESCRIBE", false},
		{"short line times out", []string{"OPTIONS rtsp://h"}, 256, "OPTIONS rtsp://h", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			go func() {
				for _, w := range tc.writes {
					_, _ = client.Write([]byte(w))
				}
			}()
			bufConn := newBufferedConn(server)
			require.NoError(t, bufConn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
			line, err := bufConn.peekLine(tc.max)
			if tc.timeout {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, string(line))
		})
	}
}
