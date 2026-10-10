package tcp

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	sshproto "github.com/mushorg/glutton/protocols/tcp/ssh"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"
)

// sshTimeout leaves room for generating the RSA host key on first use.
const sshTimeout = 20 * time.Second

// startSSH serves one connection with HandleSSH over loopback TCP; net.Pipe
// would deadlock, since both sides write their identification string first.
func startSSH(t *testing.T) (string, *fakeHoneypot, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- HandleSSH(context.Background(), conn, connection.Metadata{TargetPort: 22}, &recordingLogger{}, hp)
	}()
	return ln.Addr().String(), hp, done
}

func waitSSHEvent(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, []parsedSSH) {
	t.Helper()
	select {
	case ev := <-hp.produced:
		require.Equal(t, "ssh", ev.protocol)
		frames, ok := ev.decoded.([]parsedSSH)
		require.True(t, ok)
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(sshTimeout):
			t.Fatal("handler did not return")
		}
		require.Empty(t, hp.produced, "exactly one event per session")
		return ev, frames
	case <-time.After(sshTimeout):
		t.Fatal("timed out waiting for produced SSH event")
		return producedTCP{}, nil
	}
}

func sshFramesByCommand(frames []parsedSSH, direction, command string) []parsedSSH {
	var out []parsedSSH
	for _, f := range frames {
		if f.Direction == direction && f.Command == command {
			out = append(out, f)
		}
	}
	return out
}

func sshAuthFrames(frames []parsedSSH) []parsedSSH {
	var out []parsedSSH
	for _, f := range frames {
		if len(f.Command) > 5 && f.Command[:5] == "auth-" {
			out = append(out, f)
		}
	}
	return out
}

func sshClient(t *testing.T, addr string, auth ...cryptossh.AuthMethod) error {
	t.Helper()
	cfg := &cryptossh.ClientConfig{
		User:            "root",
		Auth:            auth,
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         sshTimeout,
	}
	client, err := cryptossh.Dial("tcp", addr, cfg)
	if err == nil {
		client.Close()
	}
	return err
}

var sshBannerWrite = parsedSSH{
	Direction: "write",
	Command:   "banner",
	Payload:   []byte(sshproto.ServerVersion + "\r\n"),
	Version:   sshproto.ServerVersion,
}

func TestSSHParamikoReplay(t *testing.T) {
	addr, hp, done := startSSH(t)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(sshTimeout)))
	_, err = conn.Write(append(append([]byte(nil), sshParamikoRead1...), sshParamikoRead2...))
	require.NoError(t, err)

	// the server answers with its banner and its own KEXINIT
	r := bufio.NewReader(conn)
	var stream sshproto.Stream
	var kex *sshproto.KexInit
	buf := make([]byte, 4096)
	for kex == nil {
		n, err := r.Read(buf)
		require.NoError(t, err)
		for _, m := range stream.Feed(buf[:n]) {
			if m.Kind == sshproto.KindVersion {
				require.Equal(t, sshproto.ServerVersion, m.Version)
			}
			kex = m.KexInit
		}
	}
	require.Equal(t, append(sshKeyExchanges, "kex-strict-s-v00@openssh.com"), kex.KexAlgos)
	require.Equal(t, []string{"rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256", "ssh-ed25519"}, kex.ServerHostKeyAlgos)
	require.Equal(t, sshCiphers, kex.CiphersServerClient)
	require.Equal(t, sshMACs, kex.MACsServerClient)
	require.NoError(t, conn.Close())

	ev, frames := waitSSHEvent(t, hp, done)
	require.Contains(t, []string{connection.EndClientClose, connection.EndClientReset}, ev.endReason)
	require.Equal(t, sshBannerWrite, frames[0])
	require.Equal(t, []parsedSSH{{
		Direction: "read",
		Command:   "banner",
		Payload:   sshParamikoRead1,
		Version:   "SSH-2.0-paramiko_2.11.0",
	}}, sshFramesByCommand(frames, "read", "banner"))

	reads := sshFramesByCommand(frames, "read", "kexinit")
	require.Len(t, reads, 1)
	require.Equal(t, sshParamikoRead2, reads[0].Payload)
	require.Equal(t, "a704be057881f0b1d623cd263e477a8b", reads[0].HASSH)
	require.Contains(t, reads[0].HASSHAlgorithms, ";aes128-ctr,")

	writes := sshFramesByCommand(frames, "write", "kexinit")
	require.Len(t, writes, 1)
	hasshServer, _ := kex.HASSH(true)
	require.Equal(t, hasshServer, writes[0].HASSH)
	require.Len(t, frames, 4)
}

func TestSSHPasswordAuth(t *testing.T) {
	addr, hp, done := startSSH(t)
	err := sshClient(t, addr, cryptossh.Password("hunter2-secret"))
	require.ErrorContains(t, err, "unable to authenticate")

	_, frames := waitSSHEvent(t, hp, done)
	require.Equal(t, sshBannerWrite, frames[0])
	require.Equal(t, "SSH-2.0-Go", sshFramesByCommand(frames, "read", "banner")[0].Version)
	require.Len(t, sshFramesByCommand(frames, "read", "kexinit"), 1)
	require.Len(t, sshFramesByCommand(frames, "write", "kexinit"), 1)
	require.Equal(t, []parsedSSH{
		{Direction: "read", Command: "auth-none", User: "root"},
		{Direction: "write", Command: "auth-none", Status: "failure"},
		{Direction: "read", Command: "auth-password", User: "root", Password: "hunter2-secret"},
		{Direction: "write", Command: "auth-password", Status: "failure"},
	}, sshAuthFrames(frames))
}

func TestSSHLongPassword(t *testing.T) {
	addr, hp, done := startSSH(t)
	long := strings.Repeat("p", sshMaxPassword+10)
	require.Error(t, sshClient(t, addr, cryptossh.Password(long)))

	_, frames := waitSSHEvent(t, hp, done)
	reads := sshFramesByCommand(frames, "read", "auth-password")
	require.Len(t, reads, 1)
	require.Equal(t, long[:sshMaxPassword], reads[0].Password)
	require.True(t, reads[0].Truncated)
}

func TestSSHPublicKeyAuth(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := cryptossh.NewSignerFromKey(key)
	require.NoError(t, err)

	addr, hp, done := startSSH(t)
	err = sshClient(t, addr, cryptossh.PublicKeys(signer))
	require.Error(t, err)

	_, frames := waitSSHEvent(t, hp, done)
	auth := sshAuthFrames(frames)
	require.Len(t, auth, 4)
	require.Empty(t, auth[2].Password)
	require.Equal(t, parsedSSH{
		Direction:         "read",
		Command:           "auth-publickey",
		User:              "root",
		PubkeyType:        "ssh-ed25519",
		PubkeyFingerprint: cryptossh.FingerprintSHA256(signer.PublicKey()),
	}, auth[2])
	require.Equal(t, "failure", auth[3].Status)
}

func TestSSHMaxAuthTries(t *testing.T) {
	addr, hp, done := startSSH(t)
	attempts := 0
	err := sshClient(t, addr, cryptossh.RetryableAuthMethod(cryptossh.PasswordCallback(func() (string, error) {
		attempts++
		return "guess", nil
	}), 20))
	require.Error(t, err)

	ev, frames := waitSSHEvent(t, hp, done)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Len(t, sshFramesByCommand(frames, "read", "auth-password"), sshMaxAuthTries)
	require.Equal(t, sshMaxAuthTries, attempts)
}

func TestSSHEarlyDisconnect(t *testing.T) {
	addr, hp, done := startSSH(t)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(sshTimeout)))
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, sshproto.ServerVersion+"\r\n", line)
	require.NoError(t, conn.Close())

	ev, frames := waitSSHEvent(t, hp, done)
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, []parsedSSH{sshBannerWrite}, frames)
}

func TestSSHGarbageAfterBanner(t *testing.T) {
	addr, hp, done := startSSH(t)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(sshTimeout)))
	garbage := []byte{0xff, 0xff, 0xff, 0xff, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05}
	_, err = conn.Write(append([]byte("SSH-2.0-x\r\n"), garbage...))
	require.NoError(t, err)

	ev, frames := waitSSHEvent(t, hp, done)
	conn.Close()
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	require.Equal(t, sshBannerWrite, frames[0])
	require.Equal(t, []parsedSSH{
		{Direction: "read", Command: "banner", Payload: []byte("SSH-2.0-x\r\n"), Version: "SSH-2.0-x"},
		{Direction: "read", Payload: garbage},
	}, append(sshFramesByCommand(frames, "read", "banner"), sshFramesByCommand(frames, "read", "")...))
}

func TestSSHNotSSH(t *testing.T) {
	addr, hp, done := startSSH(t)
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(sshTimeout)))
	_, err = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	require.NoError(t, err)
	_, err = bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	_, frames := waitSSHEvent(t, hp, done)
	require.Equal(t, []parsedSSH{
		sshBannerWrite,
		{Direction: "read", Payload: []byte("GET / HTTP/1.0\r\n\r\n"), Truncated: true},
	}, frames)
}
