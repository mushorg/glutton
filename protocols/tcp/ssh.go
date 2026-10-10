package tcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	sshproto "github.com/mushorg/glutton/protocols/tcp/ssh"

	"github.com/spf13/viper"
	cryptossh "golang.org/x/crypto/ssh"
)

// parsedSSH is one frame of an SSH session. The identification strings and
// KEXINITs carry their wire bytes; auth frames carry what the client asked
// for (user, password, public key) and the outcome.
type parsedSSH struct {
	Direction         string `json:"direction,omitempty"`
	Command           string `json:"command,omitempty"` // banner, kexinit, auth-<method>
	Status            string `json:"status,omitempty"`  // auth outcome on writes
	Payload           []byte `json:"payload,omitempty"`
	Truncated         bool   `json:"truncated,omitempty"`
	Version           string `json:"version,omitempty"` // identification string on banner frames
	HASSH             string `json:"hassh,omitempty"`   // HASSH (reads) or HASSHServer (writes) on kexinit frames
	HASSHAlgorithms   string `json:"hassh_algorithms,omitempty"`
	User              string `json:"user,omitempty"`
	Password          string `json:"password,omitempty"`
	PubkeyType        string `json:"pubkey_type,omitempty"`
	PubkeyFingerprint string `json:"pubkey_fingerprint,omitempty"`
}

// sshMaxAuthTries is the OpenSSH MaxAuthTries default; x/crypto disconnects
// with "too many authentication failures" once it is reached.
const sshMaxAuthTries = 6

// sshMaxPassword caps a recorded password; longer ones set truncated.
const sshMaxPassword = 1024

// The OpenSSH 8.9 server proposal, as far as x/crypto implements it (no
// sntrup761x25519, diffie-hellman-group18, umac, hmac-sha1-etm or zlib).
var (
	sshKeyExchanges = []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
		"diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256",
	}
	sshCiphers = []string{
		"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
	}
	sshMACs = []string{
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
	}
)

var errSSHDenied = errors.New("permission denied")

var sshHostKeys struct {
	once    sync.Once
	signers []cryptossh.Signer
	err     error
}

// sshSigners returns the host keys: the private keys listed in ssh.host_keys,
// or RSA, ECDSA and Ed25519 keys generated once per process. RSA comes first
// as on Ubuntu; x/crypto fixes the RSA order, so the offered host key
// algorithms are rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ssh-ed25519
// (OpenSSH lists rsa-sha2-512 first).
func sshSigners() ([]cryptossh.Signer, error) {
	sshHostKeys.once.Do(func() {
		if paths := viper.GetStringSlice("ssh.host_keys"); len(paths) > 0 {
			sshHostKeys.signers, sshHostKeys.err = loadSSHHostKeys(paths)
			return
		}
		sshHostKeys.signers, sshHostKeys.err = generateSSHHostKeys()
	})
	return sshHostKeys.signers, sshHostKeys.err
}

func loadSSHHostKeys(paths []string) ([]cryptossh.Signer, error) {
	signers := make([]cryptossh.Signer, 0, len(paths))
	for _, path := range paths {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		signer, err := cryptossh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("ssh host key %s: %w", path, err)
		}
		if signer, err = sshHostSigner(signer); err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

func generateSSHHostKeys() ([]cryptossh.Signer, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, err
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signers := make([]cryptossh.Signer, 0, 3)
	for _, key := range []any{rsaKey, ecdsaKey, ed25519Key} {
		signer, err := cryptossh.NewSignerFromKey(key)
		if err != nil {
			return nil, err
		}
		if signer, err = sshHostSigner(signer); err != nil {
			return nil, err
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

// sshHostSigner limits an RSA host key to the SHA-2 signatures OpenSSH 8.9
// offers; x/crypto would also offer ssh-rsa.
func sshHostSigner(signer cryptossh.Signer) (cryptossh.Signer, error) {
	if signer.PublicKey().Type() != cryptossh.KeyAlgoRSA {
		return signer, nil
	}
	algSigner, ok := signer.(cryptossh.AlgorithmSigner)
	if !ok {
		return signer, nil
	}
	return cryptossh.NewSignerWithAlgorithms(algSigner, []string{cryptossh.KeyAlgoRSASHA512, cryptossh.KeyAlgoRSASHA256})
}

type sshServer struct {
	mu        sync.Mutex
	events    []parsedSSH
	reads     sshproto.Stream
	writes    sshproto.Stream
	endReason string
	closed    bool
	produced  bool
	// pubkey is the key of the latest publickey request; x/crypto caches the
	// callback result, so a signed retry of the same key does not repeat it.
	pubkey cryptossh.PublicKey
	// password is the password of the latest password request.
	password []byte

	ctx    context.Context
	h      interfaces.Honeypot
	logger interfaces.Logger
	md     connection.Metadata
	host   string
	port   string
}

// capture frames the unencrypted start of one direction as it passes.
func (s *sshServer) capture(direction string, stream *sshproto.Stream, data []byte, ended bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.produced {
		return
	}
	msgs := stream.Feed(data)
	if ended {
		if m, ok := stream.Flush(); ok {
			msgs = append(msgs, m)
		}
	}
	for _, m := range msgs {
		s.events = append(s.events, sshFrame(direction, m))
		if direction == "read" && m.Kind == sshproto.KindVersion {
			s.logger.Info(
				"ssh client",
				slog.String("handler", "ssh"),
				slog.String("src_ip", s.host),
				slog.String("src_port", s.port),
				slog.String("dest_port", fmt.Sprint(s.md.TargetPort)),
				slog.String("version", m.Version),
			)
		}
	}
}

func sshFrame(direction string, m sshproto.Message) parsedSSH {
	f := parsedSSH{Direction: direction, Payload: m.Raw, Truncated: m.Truncated}
	switch m.Kind {
	case sshproto.KindVersion:
		f.Command = "banner"
		f.Version = m.Version
	case sshproto.KindKexInit:
		f.Command = "kexinit"
		f.HASSH, f.HASSHAlgorithms = m.KexInit.HASSH(direction == "write")
	}
	return f
}

func (s *sshServer) notePassword(password []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.password = append([]byte(nil), password...)
}

func (s *sshServer) notePublicKey(key cryptossh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pubkey = key
}

// authLog records one authentication request and its outcome.
func (s *sshServer) authLog(meta cryptossh.ConnMetadata, method string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.produced {
		return
	}
	read := parsedSSH{Direction: "read", Command: "auth-" + method, User: meta.User()}
	if method == "publickey" && s.pubkey != nil {
		read.PubkeyType = s.pubkey.Type()
		read.PubkeyFingerprint = cryptossh.FingerprintSHA256(s.pubkey)
	}
	if method == "password" {
		password := s.password
		if len(password) > sshMaxPassword {
			password = password[:sshMaxPassword]
			read.Truncated = true
		}
		read.Password = string(password)
		s.password = nil
	}
	status := "failure"
	if err == nil {
		status = "success"
	}
	s.events = append(s.events, read, parsedSSH{Direction: "write", Command: read.Command, Status: status})
	if method != "none" {
		s.logger.Info(
			"ssh login attempt",
			slog.String("handler", "ssh"),
			slog.String("src_ip", s.host),
			slog.String("src_port", s.port),
			slog.String("dest_port", fmt.Sprint(s.md.TargetPort)),
			slog.String("username", meta.User()),
			slog.String("password", read.Password),
			slog.String("method", method),
		)
	}
}

func (s *sshServer) setEndReason(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.endReason == "" && !s.closed {
		s.endReason = reason
	}
}

// sshConn is the connection x/crypto speaks over: it refreshes the idle
// timeout before every read and frames the plaintext preamble.
type sshConn struct {
	net.Conn
	s *sshServer
}

func (c *sshConn) Read(p []byte) (int, error) {
	if err := c.s.h.UpdateConnectionTimeout(c.s.ctx, c.Conn); err != nil {
		c.s.setEndReason(connection.EndTimeout)
		return 0, err
	}
	n, err := c.Conn.Read(p)
	c.s.capture("read", &c.s.reads, p[:n], err != nil)
	if err != nil {
		c.s.setEndReason(connection.EndReasonFromRead(err))
	}
	return n, err
}

func (c *sshConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.s.capture("write", &c.s.writes, p[:n], false)
	if err != nil {
		c.s.setEndReason(connection.EndWriteError)
	}
	return n, err
}

func (c *sshConn) Close() error {
	c.s.mu.Lock()
	c.s.closed = true
	c.s.mu.Unlock()
	return c.Conn.Close()
}

// HandleSSH completes the SSH key exchange with an OpenSSH persona and records
// the client's identification string, KEXINIT (with its HASSH) and every
// authentication request, rejecting all of them.
func HandleSSH(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	server := &sshServer{events: []parsedSSH{}, ctx: ctx, h: h, logger: logger, md: md, host: host, port: port}
	defer func() {
		server.mu.Lock()
		if m, ok := server.reads.Flush(); ok {
			server.events = append(server.events, sshFrame("read", m))
		}
		server.produced = true
		events := server.events
		md.EndReason = server.endReason
		if md.EndReason == "" {
			md.EndReason = connection.EndHandlerClose
		}
		server.mu.Unlock()
		if err := h.ProduceTCP("ssh", conn, md, helpers.FirstOrEmpty(events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "ssh"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SSH connection", slog.String("protocol", "ssh"), producer.ErrAttr(err))
		}
	}()

	signers, err := sshSigners()
	if err != nil {
		logger.Error("Failed to load SSH host keys", slog.String("protocol", "ssh"), producer.ErrAttr(err))
		return nil
	}
	config := &cryptossh.ServerConfig{
		Config: cryptossh.Config{
			KeyExchanges: sshKeyExchanges,
			Ciphers:      sshCiphers,
			MACs:         sshMACs,
		},
		ServerVersion: sshproto.ServerVersion,
		MaxAuthTries:  sshMaxAuthTries,
		PasswordCallback: func(_ cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
			server.notePassword(password)
			return nil, errSSHDenied
		},
		PublicKeyCallback: func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			server.notePublicKey(key)
			return nil, errSSHDenied
		},
		AuthLogCallback: server.authLog,
	}
	for _, signer := range signers {
		config.AddHostKey(signer)
	}

	sconn, chans, reqs, err := cryptossh.NewServerConn(&sshConn{Conn: conn, s: server}, config)
	if err != nil {
		logger.Debug("SSH session ended", slog.String("protocol", "ssh"), producer.ErrAttr(err))
		return nil
	}
	// every method is rejected, so this is not reached; never serve a session
	go cryptossh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			_ = ch.Reject(cryptossh.Prohibited, "administratively prohibited")
		}
	}()
	return sconn.Close()
}
