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

	log "github.com/Sirupsen/logrus"
	"github.com/lunixbochs/vtclean"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

type SSHProxy struct {
	logger     *log.Logger
	config     *ssh.ServerConfig
	callbackFn func(c ssh.ConnMetadata) (*ssh.Client, error)
	wrapFn     func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error)
	closeFn    func(c ssh.ConnMetadata) error
	reader     *ReadSession
}

type ReadSession struct {
	io.ReadCloser
	buffer    bytes.Buffer
	delimiter []byte
	n         int // Number of bytes written to buffer
}

func (g *Glutton) NewSSHProxy() (err error) {
	sshProxy := &SSHProxy{
		logger: g.logger,
	}

	dest, err := url.Parse(g.conf.GetString("proxy_ssh"))
	if err != nil {
		g.logger.Error("Failed to parse destination address, check config.yaml", "ssh.prxy")
		return err
	}

	err = sshProxy.initConf(dest.Host)
	if err != nil {
		g.logger.Error(errors.Wrap(interpreter("Connection failed at SSH Proxy: ", err), "ssh.prxy"))
		return err
	}
	g.sshProxy = sshProxy
	return
}

func (s *SSHProxy) initConf(dest string) error {
	rsaKey, err := s.SSHKeyGen()
	if err != nil {
		s.logger.Error(errors.Wrap(err, "ssh.prxy"))
		return err
	}

	private, _ := ssh.ParsePrivateKey(rsaKey)

	var sessions map[net.Addr]map[string]interface{} = make(map[net.Addr]map[string]interface{})
	conf := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.logger.Infof("[prxy.ssh] logging attempt: %s, user %s password: %s\n", c.RemoteAddr(), c.User(), string(pass))

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
		s.reader = &ReadSession{
			ReadCloser: r,
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

func (s *SSHProxy) handle(conn net.Conn) error {
	serverConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	defer conn.Close()
	if err != nil {
		s.logger.Error(errors.Wrap(interpreter("Failed to handshake", err), "ssh.prxy"))
		return (err)
	}

	clientConn, err := s.callbackFn(serverConn)
	defer clientConn.Close()
	if err != nil {
		s.logger.Error(errors.Wrap(err, "ssh.prxy"))
		return (err)
	}

	go ssh.DiscardRequests(reqs)

	for ch := range chans {

		sshClientChan, clientReq, err := clientConn.OpenChannel(ch.ChannelType(), ch.ExtraData())
		if err != nil {
			s.logger.Error(errors.Wrap(interpreter(" Could not accept client channel: ", err), "ssh.prxy"))
			return err
		}

		sshServerChan, serverReq, err := ch.Accept()
		if err != nil {
			s.logger.Error(errors.Wrap(interpreter(" Could not accept server channel: ", err), "ssh.prxy"))
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
				b, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
				if err != nil {
					s.logger.Error(errors.Wrap(err, "ssh.prxy"))
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
func (s *SSHProxy) SSHKeyGen() ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2014)
	if err != nil {
		s.logger.Error(errors.Wrap(err, "ssh.prxy"))
		return nil, err
	}
	err = priv.Validate()
	if err != nil {
		s.logger.Error(errors.Wrap(interpreter("Validation failed.", err), "ssh.prxy"))
		return nil, err
	}

	priv_der := x509.MarshalPKCS1PrivateKey(priv)

	priv_blk := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   priv_der,
	}

	RSA_Key := pem.EncodeToMemory(&priv_blk)

	// Shot to validating private bytes
	_, err = ssh.ParsePrivateKey(RSA_Key)
	if err != nil {
		s.logger.Error(errors.Wrap(err, "ssh.prxy"))
		return nil, err
	}
	return RSA_Key, nil
}

func interpreter(msg string, err error) error {
	return errors.New(fmt.Sprintf("%s  %s\n", msg, err))
}

func (rs *ReadSession) Read(p []byte) (n int, err error) {
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

func (rs *ReadSession) String() string {
	return rs.buffer.String()
}

func (rs *ReadSession) Close() error {
	return rs.ReadCloser.Close()
}

func (rs *ReadSession) collector(n int) {
	b := rs.buffer.Next(n)
	if len(b) != n {
		log.Error(errors.Wrap(interpreter("Logging is not working properly.", nil), "ssh.prxy"))
	}
	if n > 0 {
		// Clean up raw terminal output by stripping escape sequences
		line := vtclean.Clean(string(b[:]), false)
		log.Infof("[ssh.prxy] %s", line)
	}
	b = nil
}
