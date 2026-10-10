package ssh

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseKexInitParamiko(t *testing.T) {
	// packet_length 1164, padding_length 5, then the payload
	payload := paramikoRead2[5 : 4+1164-5]
	k, err := ParseKexInit(payload)
	require.NoError(t, err)
	require.Equal(t, paramikoRead2[6:22], k.Cookie)
	require.Equal(t, []string{
		"curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group16-sha512", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha256",
		"diffie-hellman-group-exchange-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "ext-info-c",
	}, k.KexAlgos)
	require.Len(t, k.ServerHostKeyAlgos, 16)
	require.Equal(t, "ssh-rsa", k.ServerHostKeyAlgos[0])
	require.Equal(t, []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"}, k.CiphersClientServer)
	require.Equal(t, k.CiphersClientServer, k.CiphersServerClient)
	require.Len(t, k.MACsClientServer, 8)
	require.Equal(t, []string{"none"}, k.CompressionClientServer)
	require.Nil(t, k.LanguagesClientServer)
	require.False(t, k.FirstKexFollows)

	hassh, algorithms := k.HASSH(false)
	// md5 of kex;ciphers_c2s;macs_c2s;compression_c2s, computed independently
	require.Equal(t, "a704be057881f0b1d623cd263e477a8b", hassh)
	require.True(t, bytes.HasPrefix([]byte(algorithms), []byte("curve25519-sha256@libssh.org,")))
	require.True(t, bytes.HasSuffix([]byte(algorithms), []byte(";none")))
}

func TestParseKexInitShort(t *testing.T) {
	payload := paramikoRead2[5 : 4+1164-5]
	for _, n := range []int{0, 1, 16, 17, 30, len(payload) - 5} {
		_, err := ParseKexInit(payload[:n])
		require.Error(t, err, "length %d", n)
	}
	wrong := append([]byte{21}, payload[1:]...)
	_, err := ParseKexInit(wrong)
	require.Error(t, err)
}

func TestStreamParamiko(t *testing.T) {
	var s Stream
	msgs := s.Feed(paramikoRead1)
	require.Len(t, msgs, 1)
	require.Equal(t, KindVersion, msgs[0].Kind)
	require.Equal(t, "SSH-2.0-paramiko_2.11.0", msgs[0].Version)
	require.Equal(t, paramikoRead1, msgs[0].Raw)

	// the KEXINIT arriving in pieces completes on the last one
	require.Empty(t, s.Feed(paramikoRead2[:3]))
	require.Empty(t, s.Feed(paramikoRead2[3:600]))
	msgs = s.Feed(append(append([]byte(nil), paramikoRead2[600:]...), 0x00, 0x00, 0x00, 0x2c))
	require.Len(t, msgs, 1)
	require.Equal(t, KindKexInit, msgs[0].Kind)
	require.Equal(t, paramikoRead2, msgs[0].Raw)
	require.NotNil(t, msgs[0].KexInit)
	require.True(t, s.Done())

	// key exchange and encrypted traffic after the KEXINIT are ignored
	require.Empty(t, s.Feed([]byte{1, 2, 3}))
	_, ok := s.Flush()
	require.False(t, ok)
}

func TestStreamPreVersionLines(t *testing.T) {
	var s Stream
	require.Empty(t, s.Feed([]byte("hello\r\n\nworld")))
	msgs := s.Feed([]byte("\nSSH-2.0-Go\r\n"))
	require.Len(t, msgs, 2)
	require.Equal(t, KindLine, msgs[0].Kind)
	require.Equal(t, []byte("hello\r\n\nworld\n"), msgs[0].Raw)
	require.Equal(t, KindVersion, msgs[1].Kind)
	require.Equal(t, "SSH-2.0-Go", msgs[1].Version)
}

func TestStreamPreVersionCap(t *testing.T) {
	var s Stream
	require.Empty(t, s.Feed(bytes.Repeat([]byte("x\n"), maxLine/2)))
	msgs := s.Feed([]byte("yy\n"))
	require.Len(t, msgs, 1)
	require.Equal(t, KindInvalid, msgs[0].Kind)
	require.Len(t, msgs[0].Raw, maxLine/2*2+3)
}

func TestStreamGarbageAfterVersion(t *testing.T) {
	var s Stream
	msgs := s.Feed([]byte("SSH-2.0-x\r\nGET / HTTP/1.1\r\n"))
	require.Len(t, msgs, 2)
	require.Equal(t, KindInvalid, msgs[1].Kind)
	require.Equal(t, []byte("GET / HTTP/1.1\r\n"), msgs[1].Raw)
	require.True(t, s.Done())
}

func TestStreamLongLine(t *testing.T) {
	var s Stream
	msgs := s.Feed(bytes.Repeat([]byte("A"), maxLine+1))
	require.Len(t, msgs, 1)
	require.Equal(t, KindInvalid, msgs[0].Kind)
	require.Len(t, msgs[0].Raw, maxLine+1)
}

func TestStreamNonKexInitPacket(t *testing.T) {
	var s Stream
	s.Feed([]byte("SSH-2.0-x\r\n"))
	// packet_length 12, padding 4, SSH_MSG_IGNORE (2) with 6 bytes of data
	pkt := []byte{0, 0, 0, 12, 4, 2, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0}
	msgs := s.Feed(pkt)
	require.Len(t, msgs, 1)
	require.Equal(t, KindPacket, msgs[0].Kind)
	require.Equal(t, pkt, msgs[0].Raw)
}

func TestStreamFlush(t *testing.T) {
	var s Stream
	require.Empty(t, s.Feed([]byte("SSH-2.0-cut")))
	m, ok := s.Flush()
	require.True(t, ok)
	require.Equal(t, KindVersion, m.Kind)
	require.Equal(t, "SSH-2.0-cut", m.Version)
	require.True(t, m.Truncated)

	var p Stream
	p.Feed(paramikoRead1)
	require.Empty(t, p.Feed(paramikoRead2[:100]))
	m, ok = p.Flush()
	require.True(t, ok)
	require.Equal(t, KindInvalid, m.Kind)
	require.Equal(t, paramikoRead2[:100], m.Raw)
	require.True(t, m.Truncated)
}
