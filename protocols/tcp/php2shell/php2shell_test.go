package php2shell

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const boundary = "----glutton"

func multipart(parts ...string) []byte {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--" + boundary + "\r\nContent-Disposition: form-data; " + p + "\r\n\r\nx\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}

func mpHeader() http.Header {
	return http.Header{"Content-Type": {"multipart/form-data; boundary=" + boundary}}
}

func TestInspectIndicators(t *testing.T) {
	t.Run("upload progress", func(t *testing.T) {
		got := Inspect(mpHeader(), multipart(`name="PHP_SESSION_UPLOAD_PROGRESS"`, `name="f"; filename="a.txt"`))
		require.Equal(t, &Request{Indicators: []string{UploadProgress}, Parts: 2, ContentLength: int64(len(multipart(`name="PHP_SESSION_UPLOAD_PROGRESS"`, `name="f"; filename="a.txt"`))), Boundary: boundary}, got)
	})

	t.Run("many parts", func(t *testing.T) {
		parts := make([]string, ManyPartsThreshold)
		for i := range parts {
			parts[i] = `name="a"`
		}
		got := Inspect(mpHeader(), multipart(parts...))
		require.NotNil(t, got)
		require.Equal(t, []string{ManyParts}, got.Indicators)
		require.Equal(t, ManyPartsThreshold, got.Parts)
	})

	t.Run("declared large body", func(t *testing.T) {
		h := mpHeader()
		h.Set("Content-Length", "268435456")
		got := Inspect(h, multipart(`name="a"`))
		require.NotNil(t, got)
		require.Equal(t, []string{LargeBody}, got.Indicators)
		require.Equal(t, int64(268435456), got.ContentLength)
	})

	t.Run("long session cookie", func(t *testing.T) {
		h := mpHeader()
		h.Set("Cookie", "a=b; PHPSESSID="+strings.Repeat("A", MaxSessionCookie+1))
		got := Inspect(h, multipart(`name="a"`))
		require.NotNil(t, got)
		require.Equal(t, []string{LongSessionCookie}, got.Indicators)
	})

	t.Run("scan cap and boundary cap", func(t *testing.T) {
		long := strings.Repeat("b", MaxBoundary+1)
		h := http.Header{"Content-Type": {"multipart/form-data; boundary=" + long}}
		got := Inspect(h, []byte(strings.Repeat("x", MaxScan+1)))
		require.NotNil(t, got)
		require.True(t, got.Truncated)
		require.Len(t, got.Boundary, MaxBoundary)
	})
}

func TestInspectIgnoresOrdinaryRequests(t *testing.T) {
	require.Nil(t, Inspect(mpHeader(), multipart(`name="f"; filename="a.txt"`)), "plain upload")
	require.Nil(t, Inspect(http.Header{}, nil), "no content type")
	require.Nil(t, Inspect(http.Header{"Content-Type": {"application/json"}}, []byte("PHP_SESSION_UPLOAD_PROGRESS")), "not multipart")
	require.Nil(t, Inspect(http.Header{"Content-Type": {"multipart/form-data; bad"}}, nil), "malformed media type")
}

// scannerProbe rebuilds build_probe_body from the public Assetnote scanner
// (github.com/assetnote/php2shell-scanner): LF-only, empty boundary, filler
// "x:" lines, then parts whose name is a[] plus 62 [a] levels.
func scannerProbe(sizeMiB, parts int) []byte {
	part := []byte("--\nContent-Disposition:name=a[]" + strings.Repeat("[a]", 62) + ";filename=\n\n")
	base := bytes.Repeat(part, parts)
	filler := ((sizeMiB << 20) - len(base)) / 3
	body := append([]byte("--\n"), bytes.Repeat([]byte("x:\n"), filler)...)
	body = append(body, base[3:]...)
	return body[:len(body)-1]
}

func scannerHeader(boundary string, size int) http.Header {
	return http.Header{
		"Content-Type":   {"multipart/form-data; boundary=" + boundary},
		"Content-Length": {strconv.Itoa(size)},
		"User-Agent":     {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 PHP2Shell/1.0.0"},
	}
}

func TestInspectScannerProbes(t *testing.T) {
	t.Run("1 MiB probe, body read in full", func(t *testing.T) {
		body := scannerProbe(1, 4000)
		got := Inspect(scannerHeader("", len(body)), body)
		require.Equal(t, &Request{
			Indicators:    []string{EmptyBoundary, ManyParts, NestedName, ScannerUserAgent},
			Parts:         4000,
			ContentLength: int64(len(body)),
			MaxDepth:      63,
		}, got)
	})

	// The HTTP handler does not read bodies over 1 MiB, so only headers arrive.
	t.Run("20 MiB probe, headers only", func(t *testing.T) {
		got := Inspect(scannerHeader("", 20<<20), nil)
		require.Equal(t, &Request{
			Indicators:    []string{EmptyBoundary, LargeBody, ScannerUserAgent},
			ContentLength: 20 << 20,
		}, got)
	})

	t.Run("control request", func(t *testing.T) {
		body := []byte("--x\nContent-Disposition:name=a;filename=\n\n")
		got := Inspect(scannerHeader("x", len(body)), body)
		require.Equal(t, &Request{
			Indicators:    []string{ScannerUserAgent},
			Parts:         1,
			ContentLength: int64(len(body)),
			Boundary:      "x",
		}, got)
	})

	t.Run("without the scanner User-Agent", func(t *testing.T) {
		body := scannerProbe(1, 4000)
		h := scannerHeader("", len(body))
		h.Del("User-Agent")
		got := Inspect(h, body)
		require.NotNil(t, got)
		require.Equal(t, []string{EmptyBoundary, ManyParts, NestedName}, got.Indicators)
	})
}

func TestInspectNestedName(t *testing.T) {
	deep := `name="a` + strings.Repeat("[b]", NestedNameThreshold) + `"; filename="x"`
	got := Inspect(mpHeader(), multipart(deep))
	require.NotNil(t, got)
	require.Equal(t, []string{NestedName}, got.Indicators)
	require.Equal(t, NestedNameThreshold, got.MaxDepth)

	require.Nil(t, Inspect(mpHeader(), multipart(`name="user[address][city]"`, `name="f"; filename="a[1].txt"`)), "shallow form arrays")
}
