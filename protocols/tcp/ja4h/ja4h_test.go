package ja4h

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFingerprint(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: a\r\nUser-Agent: x\r\nAccept-Language: en-US,en;q=0.9\r\nCookie: b=2; a=1\r\nReferer: http://r/\r\n\r\n")
	fp := Fingerprint(raw)
	require.Regexp(t, `^ge11cr03enus_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$`, fp)
	require.Equal(t, hash("Host,User-Agent,Accept-Language", false), fp[13:25])
	require.Equal(t, hash("a,b", false), fp[26:38])
	require.Equal(t, hash("a=1,b=2", false), fp[39:])
}

func TestFingerprintNoCookiesNoLanguage(t *testing.T) {
	require.Equal(t, "po10nn010000_"+hash("Host", false)+"_000000000000_000000000000",
		Fingerprint([]byte("POST /x HTTP/1.0\r\nHost: a\r\n\r\nbody")))
}

func TestFingerprintMalformed(t *testing.T) {
	require.Empty(t, Fingerprint([]byte("\x16\x03\x01")))
	require.Empty(t, Fingerprint(nil))
}
