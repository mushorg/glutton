package dtls

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured ClientHello (Ochi event bcbf3d9e-e2c6-4a69-abf8-fc015ead520a).
const capturedHex = "16feff000000000000000000360100002a000000000000002afefd" +
	"000000007c77401e8ac822a0a018ff9308caac0a642fc92264bc08a816891930" +
	"00" + "00" + "0002002f" + "0100"

func captured(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(capturedHex)
	require.NoError(t, err)
	require.Len(t, b, 67)
	return b
}

func TestParseCaptured(t *testing.T) {
	data := captured(t)
	require.True(t, LooksLikeDTLS(data))
	ch, err := ParseClientHello(data)
	require.NoError(t, err)
	require.Equal(t, VersionDTLS10, ch.RecordVersion)
	require.Zero(t, ch.Epoch)
	require.Zero(t, ch.Sequence)
	require.Zero(t, ch.MessageSeq)
	require.Equal(t, VersionDTLS12, ch.ClientVersion)
	require.Equal(t, data[27:59], ch.Random)
	require.Empty(t, ch.SessionID)
	require.Empty(t, ch.Cookie)
	require.Equal(t, []uint16{0x002f}, ch.CipherSuites)
	require.Equal(t, []byte{0}, ch.Compression)
	require.Empty(t, ch.Extensions)
	require.Equal(t, "DTLS 1.2", VersionString(ch.ClientVersion))
}

// withExtensions builds a ClientHello with a session ID, cookie and SNI.
func withExtensions(seq byte) []byte {
	sni := []byte{0, 12, 0, 0, 9, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'x'}
	exts := append([]byte{0, 0, 0, byte(len(sni))}, sni...)
	exts = append(exts, 0, 0x17, 0, 0) // extended_master_secret
	body := []byte{0xfe, 0xfd}
	body = append(body, make([]byte, 32)...)
	body = append(body, 2, 0xaa, 0xbb) // session ID
	body = append(body, 3, 1, 2, 3)    // cookie
	body = append(body, 0, 4, 0xc0, 0x2b, 0x00, 0x2f)
	body = append(body, 1, 0)
	body = append(body, 0, byte(len(exts)))
	body = append(body, exts...)
	h := []byte{1, 0, 0, byte(len(body)), 0, 1, 0, 0, 0, 0, 0, byte(len(body))}
	rec := append(h, body...)
	out := []byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, seq, 0, byte(len(rec))}
	return append(out, rec...)
}

func TestParseExtensionsAndCookie(t *testing.T) {
	data := withExtensions(7)
	require.True(t, LooksLikeDTLS(data))
	ch, err := ParseClientHello(data)
	require.NoError(t, err)
	require.Equal(t, uint64(7), ch.Sequence)
	require.Equal(t, uint16(1), ch.MessageSeq)
	require.Equal(t, []byte{0xaa, 0xbb}, ch.SessionID)
	require.Equal(t, []byte{1, 2, 3}, ch.Cookie)
	require.Equal(t, []uint16{0xc02b, 0x002f}, ch.CipherSuites)
	require.Equal(t, "example.x", ch.ServerName)
	require.Len(t, ch.Extensions, 2)
	require.Equal(t, uint16(0x17), ch.Extensions[1].Type)
}

func TestParseMalformed(t *testing.T) {
	data := captured(t)

	_, err := ParseClientHello(nil)
	require.ErrorIs(t, err, ErrTruncated)

	// Truncated at every length: never panics, never a nil hello once the
	// record header is readable.
	for n := 0; n < len(data); n++ {
		ch, err := ParseClientHello(data[:n])
		require.Error(t, err, "len %d", n)
		if n >= recordHeaderLen {
			require.NotNil(t, ch, "len %d", n)
		}
		require.False(t, LooksLikeDTLS(data[:n]), "len %d", n)
	}

	bad := append([]byte(nil), data...)
	bad[0] = 23
	_, err = ParseClientHello(bad)
	require.Error(t, err)
	require.False(t, LooksLikeDTLS(bad))

	bad = append([]byte(nil), data...)
	bad[2] = 0xfc // not a DTLS version
	_, err = ParseClientHello(bad)
	require.Error(t, err)
	require.False(t, LooksLikeDTLS(bad))

	bad = append([]byte(nil), data...)
	bad[13] = 2 // ServerHello
	_, err = ParseClientHello(bad)
	require.Error(t, err)
	require.False(t, LooksLikeDTLS(bad))

	bad = append([]byte(nil), data...)
	bad[3] = 1 // epoch 1: encrypted, not a hello we can read
	require.False(t, LooksLikeDTLS(bad))

	bad = append([]byte(nil), data...)
	bad[22] = 0x10 // fragment_length != length: fragmented hello
	_, err = ParseClientHello(bad)
	require.Error(t, err)
	require.False(t, LooksLikeDTLS(bad))

	bad = append([]byte(nil), data...)
	bad[59] = 0xff // session ID length runs past the body
	ch, err := ParseClientHello(bad)
	require.ErrorIs(t, err, ErrTruncated)
	require.Equal(t, VersionDTLS12, ch.ClientVersion)
}

func TestCookie(t *testing.T) {
	secret := []byte("secret")
	ip := net.ParseIP("203.0.113.9")
	c := Cookie(secret, ip, 4444)
	require.Len(t, c, CookieLen)
	require.Equal(t, c, Cookie(secret, ip, 4444))
	require.Equal(t, c, Cookie(secret, ip.To4(), 4444))
	require.NotEqual(t, c, Cookie(secret, ip, 4445))
	require.NotEqual(t, c, Cookie(secret, net.ParseIP("203.0.113.10"), 4444))
	require.NotEqual(t, c, Cookie([]byte("other"), ip, 4444))
}

func TestBuildHelloVerifyRequest(t *testing.T) {
	cookie := []byte("0123456789abcdef")
	got := BuildHelloVerifyRequest(0x0102030405, cookie)
	want := []byte{
		22, 0xfe, 0xff, 0, 0, // record: type, version, epoch
		0, 1, 2, 3, 4, 5, // sequence
		0, 31, // record length
		3, 0, 0, 19, // HelloVerifyRequest, length
		0, 0, 0, 0, 0, 0, 0, 19, // message_seq, fragment offset, fragment length
		0xfe, 0xff, 16, // server_version, cookie length
	}
	require.Equal(t, append(want, cookie...), got)
	require.Len(t, got, 44)

	// The reply is a well-formed record: it is not itself a ClientHello.
	require.False(t, LooksLikeDTLS(got))
}
