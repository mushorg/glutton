package ssh

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAuthorizedKeys(t *testing.T) {
	require.True(t, IsAuthorizedKeys("/root/.ssh/authorized_keys"))
	require.True(t, IsAuthorizedKeys("/home/simo/.ssh/authorized_keys"))
	require.True(t, IsAuthorizedKeys("/home/simo/.ssh/authorized_keys2"))
	require.False(t, IsAuthorizedKeys("/home/simo/authorized_keys"))
	require.False(t, IsAuthorizedKeys("/tmp/.ssh/known_hosts"))
	require.False(t, IsAuthorizedKeys(""))
}

// streamClient frames a captured client banner and KEXINIT.
func streamClient(t *testing.T, frames ...[]byte) (string, *KexInit) {
	t.Helper()
	var s Stream
	var msgs []Message
	for _, f := range frames {
		msgs = append(msgs, s.Feed(f)...)
	}
	require.Len(t, msgs, 2)
	require.Equal(t, KindVersion, msgs[0].Kind)
	require.Equal(t, KindKexInit, msgs[1].Kind)
	return msgs[0].Version, msgs[1].KexInit
}

func TestSpoofedOpenSSHCaptured(t *testing.T) {
	version, k := streamClient(t, spoofedGoRead1, spoofedGoRead2)
	require.Equal(t, "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7", version)
	hassh, _ := k.HASSH(false)
	require.Equal(t, "9052c4ab4164c78256e71143dcfc7eac", hassh)
	require.True(t, SpoofedOpenSSH(version, k))
}

func TestSpoofedOpenSSHParamikoNotOpenSSH(t *testing.T) {
	// paramiko offers legacy algorithms but does not claim to be OpenSSH
	version, k := streamClient(t, paramikoRead1, paramikoRead2)
	require.False(t, SpoofedOpenSSH(version, k))
	require.False(t, SpoofedOpenSSH("SSH-2.0-OpenSSH_9.2p1", nil))
}

func TestSpoofedOpenSSH(t *testing.T) {
	// the OpenSSH 9.6 client default proposal
	openssh := &KexInit{
		KexAlgos:                strings.Split("sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com", ","),
		ServerHostKeyAlgos:      strings.Split("ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256", ","),
		CiphersClientServer:     strings.Split("chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com", ","),
		CiphersServerClient:     strings.Split("chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com", ","),
		MACsClientServer:        strings.Split("umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1", ","),
		MACsServerClient:        strings.Split("umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1", ","),
		CompressionClientServer: []string{"none", "zlib@openssh.com"},
		CompressionServerClient: []string{"none", "zlib@openssh.com"},
	}
	require.False(t, SpoofedOpenSSH("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19", openssh))

	arcfour := *openssh
	arcfour.CiphersClientServer = append([]string{"arcfour256"}, openssh.CiphersClientServer...)
	require.True(t, SpoofedOpenSSH("SSH-2.0-OpenSSH_9.6p1", &arcfour))
	require.True(t, SpoofedOpenSSH("SSH-2.0-OpenSSH_7.6", &arcfour))
	// OpenSSH before 7.6 still compiled arcfour in
	require.False(t, SpoofedOpenSSH("SSH-2.0-OpenSSH_7.4", &arcfour))
	require.False(t, SpoofedOpenSSH("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2", &arcfour))

	repeated := *openssh
	repeated.ServerHostKeyAlgos = append([]string{"ssh-ed25519"}, openssh.ServerHostKeyAlgos...)
	require.True(t, SpoofedOpenSSH("SSH-2.0-OpenSSH_5.3", &repeated))

	// not an OpenSSH banner
	require.False(t, SpoofedOpenSSH("SSH-2.0-Go", &repeated))
	require.False(t, SpoofedOpenSSH("SSH-2.0-libssh_0.9.6", &arcfour))
	require.False(t, SpoofedOpenSSH("SSH-2.0-OpenSSH", &arcfour))
	require.False(t, SpoofedOpenSSH("SSH-2.0-OpenSSH_x.1", &arcfour))
}

func TestOpenSSHVersion(t *testing.T) {
	for _, tc := range []struct {
		version      string
		major, minor int
		ok           bool
	}{
		{"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u9", 9, 2, true},
		{"SSH-1.99-OpenSSH_7.6", 7, 6, true},
		{"SSH-2.0-OpenSSH_10.0", 10, 0, true},
		{"SSH-2.0-OpenSSH_for_Windows_8.1", 0, 0, false},
		{"SSH-2.0-PuTTY_Release_0.81", 0, 0, false},
		{"garbage", 0, 0, false},
	} {
		major, minor, ok := openSSHVersion(tc.version)
		require.Equal(t, tc.ok, ok, tc.version)
		require.Equal(t, tc.major, major, tc.version)
		require.Equal(t, tc.minor, minor, tc.version)
	}
}

// TestPersonasAvoidHoneypotDefaults keeps the personas off banners other
// honeypots ship as defaults, which scanners already list.
func TestPersonasAvoidHoneypotDefaults(t *testing.T) {
	for _, banner := range []string{
		"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7", // Trapster
		"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",  // Cowrie
	} {
		require.NotContains(t, PersonaVersions(), banner)
	}
}
