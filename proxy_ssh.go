package glutton

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"

	"github.com/lunixbochs/vtclean"
	log "go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type sshProxy struct {
	logger     *log.Logger
	config     *ssh.ServerConfig
	callbackFn func(c ssh.ConnMetadata) (*ssh.Client, error)
	wrapFn     func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error)
	closeFn    func(c ssh.ConnMetadata) error
	reader     *readSession
}

type readSession struct {
	io.ReadCloser
	logger    *log.Logger
	buffer    bytes.Buffer
	delimiter []byte
	n         int // Number of bytes written to buffer
}

// NewSSHProxy creates a new SSH proxy instance
func (g *Glutton) NewSSHProxy(destinationURL string) (err error) {
	sshProxy := &sshProxy{
		logger: g.logger,
	}

	dest, err := url.Parse(destinationURL)
	if err != nil {
		g.logger.Error("[ssh.prxy] failed to parse destination address, check config.yaml")
		return err
	}

	err = sshProxy.initConf(dest.Host)
	if err != nil {
		g.logger.Error(fmt.Sprintf("[ssh.prxy] connection failed at SSH proxy, error: %v", err))
		return err
	}
	g.sshProxy = sshProxy
	return
}

func (s *sshProxy) initConf(dest string) error {
	rsaKey, err := s.sshKeyGen()
	if err != nil {
		s.logger.Error(fmt.Sprintf("[ssh.prxy] %v", err))
		return err
	}

	private, _ := ssh.ParsePrivateKey(rsaKey)

	var sessions = make(map[net.Addr]map[string]interface{})
	conf := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.logger.Info(fmt.Sprintf("[prxy.ssh] login attempt: %s, user %s password: %s", c.RemoteAddr(), c.User(), string(pass)))

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
		s.logger.Debug(fmt.Sprintf("[prxy.ssh] %v", meta))
		client := meta["client"].(*ssh.Client)
		s.logger.Info(fmt.Sprintf("[prxy.ssh] connection accepted from: %s\n", c.RemoteAddr()))
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
		s.logger.Info(fmt.Sprintf("[prxy.ssh] connection closed."))
		return nil
	}

	return nil
}

func (s *sshProxy) handle(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			s.logger.Error(fmt.Sprintf("[ssh.prxy]  error: %v", err))
		}
	}()

	serverConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)

	if err != nil {
		s.logger.Error(fmt.Sprintf("[ssh.prxy] failed to handshake, error: %v", err))
		return err
	}

	clientConn, err := s.callbackFn(serverConn)
	defer func() {
		err = clientConn.Close()
		if err != nil {
			s.logger.Error(fmt.Sprintf("[ssh.prxy]  error: %v", err))
		}
	}()

	if err != nil {
		s.logger.Error(fmt.Sprintf("[ssh.prxy] error: %v", err))
		return err
	}

	go ssh.DiscardRequests(reqs)

	for ch := range chans {

		sshClientChan, clientReq, err := clientConn.OpenChannel(ch.ChannelType(), ch.ExtraData())
		if err != nil {
			s.logger.Error(fmt.Sprintf("[ssh.prxy] could not accept client channel, error: %v", err))
			return err
		}

		sshServerChan, serverReq, err := ch.Accept()
		if err != nil {
			s.logger.Error(fmt.Sprintf("[ssh.prxy] could not accept server channel, error: %+v", err))
			return err
		}

		// Connect requests of ssh server and client
		go func() {
			s.logger.Debug("[prxy.ssh] waiting for request")

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
					s.logger.Debug("[prxy.ssh] SSH request is nil")
					return
				}

				s.logger.Debug(fmt.Sprintf("[ssh.prxy] request: \n\n%s %s %v %s\n\n", dst, req.Type, req.WantReply, req.Payload))
				b, sendErr := dst.SendRequest(req.Type, req.WantReply, req.Payload)
				if sendErr != nil {
					s.logger.Error(fmt.Sprintf("[ssh.prxy] error: %v", sendErr))
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
					s.logger.Debug(fmt.Sprintf("[ssh.prxy]  %s", req.Type))
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
				s.logger.Error(fmt.Sprintf("[ssh.prxy] error: %v", err))
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
		s.logger.Error(fmt.Sprintf("[ssh.prxy] error: %v", err))
		return nil, err
	}
	err = priv.Validate()
	if err != nil {
		s.logger.Error(fmt.Sprintf("[ssh.prxy] validation failed, error: %v", err))
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
		s.logger.Error(fmt.Sprintf("[ssh.prxy] error: %v", err))
		return nil, err
	}
	return RSAKey, nil
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
		rs.logger.Error("[ssh.prxy] collector is unable to collect logs properly")
	}
	if n > 0 {
		// Clean up raw terminal output by stripping escape sequences
		line := vtclean.Clean(string(b[:]), false)
		rs.logger.Info(fmt.Sprintf("[ssh.prxy] %s", line))
	}
}
