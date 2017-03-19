package glutton

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"

	"github.com/kung-foo/freki"
	"github.com/lunixbochs/vtclean"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type sshProxy struct {
	logger     freki.Logger
	config     *ssh.ServerConfig
	callbackFn func(c ssh.ConnMetadata) (*ssh.Client, error)
	wrapFn     func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error)
	closeFn    func(c ssh.ConnMetadata) error
	reader     *readSession
}

type readSession struct {
	io.ReadCloser
	logger    freki.Logger
	buffer    bytes.Buffer
	delimiter []byte
	n         int // Number of bytes written to buffer
}

// NewSSHProxy creates a new SSH proxy instance
func (g *Glutton) NewSSHProxy() (err error) {
	sshProxy := &sshProxy{
		logger: g.logger,
	}

	dest, err := url.Parse(g.conf.GetString("proxy_ssh"))
	if err != nil {
		g.logger.Error("Failed to parse destination address, check config.yaml", "[ssh.prxy]")
		return err
	}

	err = sshProxy.initConf(dest.Host)
	if err != nil {
		g.logger.Error(errors.Wrap(formatErrorMsg("Connection failed at SSH Proxy: ", err), "[ssh.prxy]"))
		return err
	}
	g.sshProxy = sshProxy
	return
}

func (s *sshProxy) initConf(dest string) error {
	rsaKey, err := s.sshKeyGen()
	if err != nil {
		s.logger.Error(errors.Wrap(err, "[ssh.prxy]"))
		return err
	}

	private, _ := ssh.ParsePrivateKey(rsaKey)

	var sessions = make(map[net.Addr]map[string]interface{})
	conf := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.logger.Infof("[prxy.ssh] login attempt: %s, user %s password: %s", c.RemoteAddr(), c.User(), string(pass))

			sessions[c.RemoteAddr()] = map[string]interface{}{
				"username": c.User(),
				"password": string(pass),
			}

			clientConfig := &ssh.ClientConfig{
				User: c.User(),
				Auth: []ssh.AuthMethod{
					ssh.Password(string(pass)),
				},
			}

			n := 0
		try:
			client, err := ssh.Dial("tcp", dest, clientConfig)
			if err != nil && n < 2 {
				n++
				goto try
			}
			sessions[c.RemoteAddr()]["client"] = client
			return nil, err
		},
	}

	conf.AddHostKey(private)

	s.config = conf

	s.callbackFn = func(c ssh.ConnMetadata) (*ssh.Client, error) {
		meta, _ := sessions[c.RemoteAddr()]
		s.logger.Infof("[prxy.ssh] %v", meta)
		client := meta["client"].(*ssh.Client)
		s.logger.Infof("[prxy.ssh] Connection accepted from: %s\n", c.RemoteAddr())
		return client, nil
	}
	s.wrapFn = func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error) {
		s.reader = &readSession{
			ReadCloser: r,
			logger:     s.logger,
			delimiter:  []byte("\n"),
		}
		return s.reader, nil
	}
	s.closeFn = func(c ssh.ConnMetadata) error {
		s.logger.Infof("[prxy.ssh] Connection closed.")
		return nil
	}

	return nil
}

func (s *sshProxy) handle(conn net.Conn) error {
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	defer conn.Close()
	if err != nil {
		s.logger.Error(errors.Wrap(formatErrorMsg("Failed to handshake", err), "[ssh.prxy]"))
		return (err)
	}

	clientConn, err := s.callbackFn(serverConn)
	defer clientConn.Close()
	if err != nil {
		s.logger.Error(errors.Wrap(err, "[ssh.prxy]"))
		return (err)
	}

	go ssh.DiscardRequests(reqs)

	for ch := range chans {

		sshClientChan, clientReq, err := clientConn.OpenChannel(ch.ChannelType(), ch.ExtraData())
		if err != nil {
			s.logger.Error(errors.Wrap(formatErrorMsg(" Could not accept client channel: ", err), "[ssh.prxy]"))
			return err
		}

		sshServerChan, serverReq, err := ch.Accept()
		if err != nil {
			s.logger.Error(errors.Wrap(formatErrorMsg(" Could not accept server channel: ", err), "[ssh.prxy]"))
			return err
		}

		// Connect requests of ssh server and client
		go func() {
			s.logger.Debug("[prxy.ssh] Waiting for request")

		r:
			for {
				var req *ssh.Request
				var dst ssh.Channel

				select {
				case req = <-serverReq:
					dst = sshClientChan
				case req = <-clientReq:
					dst = sshServerChan
				}

				// Check if connection is closed
				if req == nil {
					s.logger.Debug("[prxy.ssh] SSH Request is nil")
					return
				}

				s.logger.Debugf("[prxy.ssh] Request: \n\n%s %s %s %s\n\n", dst, req.Type, req.WantReply, req.Payload)
				b, sendErr := dst.SendRequest(req.Type, req.WantReply, req.Payload)
				if sendErr != nil {
					s.logger.Error(errors.Wrap(sendErr, "[ssh.prxy]"))
				}

				if req.WantReply {
					req.Reply(b, nil)
				}

				switch req.Type {
				case "exit-status":
					break r
				case "exec":
					s.logger.Debug("[prxy.ssh] SSH request 'EXEC' is not supported")
				default:
					s.logger.Debugf("[prxy.ssh] %s", req.Type)
				}
			}

			sshServerChan.Close()
			sshClientChan.Close()
		}()

		var wrappedServerChan io.ReadCloser = sshServerChan
		var wrappedClientChan io.ReadCloser = sshClientChan

		defer wrappedServerChan.Close()
		defer wrappedClientChan.Close()

		if s.wrapFn != nil {
			wrappedClientChan, err = s.wrapFn(serverConn, sshClientChan)
			if err != nil {
				s.logger.Error(errors.Wrap(err, "[ssh.prxy]"))
			}
		}

		go io.Copy(sshClientChan, wrappedServerChan)
		go io.Copy(sshServerChan, wrappedClientChan)
	}

	if s.closeFn != nil {
		s.closeFn(serverConn)
	}

	return nil
}

// TODO: Use of existing key
func (s *sshProxy) sshKeyGen() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		s.logger.Error(errors.Wrap(err, "[ssh.prxy]"))
		return nil, err
	}
	err = priv.Validate()
	if err != nil {
		s.logger.Error(errors.Wrap(formatErrorMsg("Validation failed.", err), "[ssh.prxy]"))
		return nil, err
	}

	privDer := x509.MarshalPKCS1PrivateKey(priv)

	privBlk := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}

	RSAKey := pem.EncodeToMemory(&privBlk)

	// Shot to validating private bytes
	_, err = ssh.ParsePrivateKey(RSAKey)
	if err != nil {
		s.logger.Error(errors.Wrap(err, "[ssh.prxy]"))
		return nil, err
	}
	return RSAKey, nil
}

func formatErrorMsg(msg string, err error) error {
	return fmt.Errorf("%s: %s", msg, err)
}

func (rs *readSession) Read(p []byte) (n int, err error) {
	n, err = rs.ReadCloser.Read(p)

	if bytes.Contains(p[:n], rs.delimiter) {
		rs.buffer.Write(p[:n])
		go rs.collector((rs.n + n))
		rs.n = 0
	} else {
		rs.buffer.Write(p[:n])
		rs.n += n
	}
	return n, err
}

func (rs *readSession) String() string {
	return rs.buffer.String()
}

func (rs *readSession) Close() error {
	return rs.ReadCloser.Close()
}

func (rs *readSession) collector(n int) {
	b := rs.buffer.Next(n)
	if len(b) != n {
		rs.logger.Error(errors.Wrap(formatErrorMsg("Logging is not working properly.", nil), "[ssh.prxy]"))
	}
	if n > 0 {
		// Clean up raw terminal output by stripping escape sequences
		line := vtclean.Clean(string(b[:]), false)
		rs.logger.Infof("[ssh.prxy] %s", line)
	}
}
