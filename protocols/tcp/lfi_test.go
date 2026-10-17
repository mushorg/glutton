package tcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractLFITarget(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain path", "/index.html", ""},
		{"query file", "q=lfi&file=../../etc/passwd", "/etc/passwd"},
		{"encoded query", "file=..%2F..%2Fetc%2Fpasswd", "/etc/passwd"},
		{"path traversal encoded", "/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "/etc/passwd"},
		{"path traversal decoded", "/../../../../../../etc/passwd", "/etc/passwd"},
		{"path hosts", "/../../../etc/hosts", "/etc/hosts"},
		{"unknown basename still extracted", "/../../../../tmp/secret", "/tmp/secret"},
		{"null byte query", "page=/etc/passwd%00.php", "/etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, extractLFITarget(tt.in))
		})
	}
}

func TestLFIResponsePathAndQuery(t *testing.T) {
	passwd, err := Res.ReadFile("resources/lfi/passwd")
	require.NoError(t, err)

	t.Run("query", func(t *testing.T) {
		resp := LFIResponse("/search", "file=../../etc/passwd")
		require.NotNil(t, resp)
		require.Contains(t, string(resp), "Content-Type: text/plain")
		require.True(t, strings.HasSuffix(string(resp), string(passwd)))
	})

	t.Run("path only", func(t *testing.T) {
		resp := LFIResponse("/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", "")
		require.NotNil(t, resp)
		require.Contains(t, string(resp), "Content-Type: text/plain")
		require.True(t, strings.HasSuffix(string(resp), string(passwd)))
	})

	t.Run("no match", func(t *testing.T) {
		require.Nil(t, LFIResponse("/index.html", ""))
		require.Nil(t, LFIResponse("", "q=hello"))
		require.Nil(t, LFIResponse("/../../../../tmp/secret", ""))
	})
}
