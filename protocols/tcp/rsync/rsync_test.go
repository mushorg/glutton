package rsync

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseGreeting(t *testing.T) {
	// read frame 1 of the tcp/873 catch-all event from 134.185.88.23
	// (2026-10-24T17:46:57Z)
	version, digests, ok := ParseGreeting("@RSYNCD: 31.0\n")
	require.True(t, ok)
	require.Equal(t, "31.0", version)
	require.Empty(t, digests)

	version, digests, ok = ParseGreeting("@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4\r\n")
	require.True(t, ok)
	require.Equal(t, "31.0", version)
	require.Equal(t, "sha512 sha256 sha1 md5 md4", digests)

	for _, line := range []string{"backup\n", "@RSYNCD: \n", "@RSYNCD: x.0\n", "@RSYNCD: 31\n", "@RSYNCD:31.0\n", ""} {
		_, _, ok := ParseGreeting(line)
		require.False(t, ok, line)
	}
}

func TestLooksLikeGreeting(t *testing.T) {
	require.True(t, LooksLikeGreeting([]byte("@RSYNCD: 29.0\n")))
	require.False(t, LooksLikeGreeting([]byte("@RSYNC")))
	require.False(t, LooksLikeGreeting([]byte("GET / HTTP/1.1\r\n")))
}

func TestModuleLines(t *testing.T) {
	require.True(t, IsListRequest("\n"))
	require.True(t, IsListRequest("#list\r\n"))
	require.False(t, IsListRequest("backup\n"))
	require.Equal(t, "backup", ModuleName("backup/etc/passwd\n"))
	require.True(t, HasModule("www"))
	require.False(t, HasModule("WWW"))
}

func TestModuleList(t *testing.T) {
	require.Equal(t, "backup         \tNightly backups\n"+
		"www            \tWeb root\n"+
		"data           \tShared data\n"+
		"@RSYNCD: EXIT\n", string(ModuleList()))
}

func TestAuth(t *testing.T) {
	challenge, err := NewChallenge(bytes.NewReader(make([]byte, 16)))
	require.NoError(t, err)
	require.Equal(t, "AAAAAAAAAAAAAAAAAAAAAA", challenge)
	_, err = NewChallenge(bytes.NewReader(nil))
	require.Error(t, err)

	require.Equal(t, "@RSYNCD: AUTHREQD abc\n", string(AuthRequired("abc")))
	user, resp := ParseAuth("root fKQLnHeZxhRbHalXnTnOqg\n")
	require.Equal(t, "root", user)
	require.Equal(t, "fKQLnHeZxhRbHalXnTnOqg", resp)
	require.Equal(t, "@ERROR: auth failed on module www\n", string(AuthFailed("www")))
	require.Equal(t, "@ERROR: Unknown module 'x'\n", string(UnknownModule("x")))
}
