package php2shell

import (
	"net/http"
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
