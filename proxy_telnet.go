package glutton

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/mushorg/glutton/protocols"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

//telnetProxy Struct
type telnetProxy struct {
	logger  *zap.Logger
	glutton *Glutton
	host    string
}

//NewTelnetProxy Create a new Telnet Proxy Session
func (g *Glutton) NewTelnetProxy(destinationURL string) error {
	t := &telnetProxy{
		logger:  g.Logger,
		glutton: g,
	}

	dest, err := url.Parse(destinationURL)
	if err != nil {
		return errors.Wrap(err, "failed to parse destination address, check config.yaml")
	}
	t.host = dest.Host
	g.telnetProxy = t
	return nil
}

//handle Telnet Proxy handler
func (t *telnetProxy) handle(ctx context.Context, conn net.Conn) error {
	ended := false
	g := t.glutton
	tcpAddr, err := net.ResolveTCPAddr("tcp", t.host)
	if err != nil {
		return errors.Wrap(err, "ResolveTCPAddr failed")
	}
	hconn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		return errors.Wrap(err, "connection error")
	}
	go func() {
		defer func() {
			ended = true
			conn.Close()
			hconn.Close()
		}()
		for {
			g.UpdateConnectionTimeout(ctx, conn)
			if ended || hconn == nil || conn == nil {
				break
			}
			reply := make([]byte, 8*1024)
			if _, err = hconn.Read(reply); err != nil {
				if err == io.EOF {
					t.logger.Error("connection closed by Server", zap.Error(err))
					break
				}
				t.logger.Error("failed to read telnet message", zap.Error(err))
				break
			}

			t.logger.Info(fmt.Sprintf("Recieved: %d bytes(s) from Server. Bytes: %s", len(string(reply)), string(reply)))
			err = protocols.WriteTelnetMsg(conn, string(reply), g.Logger, g)
			if err != nil {
				t.logger.Error("failed to write telnet message", zap.Error(err))
				break
			}
		}
	}()
	go func() {
		defer func() {
			ended = true
			conn.Close()
			hconn.Close()
		}()
		for {
			if ended || hconn == nil || conn == nil {
				return
			}
			msg, err := protocols.ReadTelnetMsg(conn, g.Logger, g)
			if err != nil {
				t.logger.Error("failed to read telnet message", zap.Error(err))
				break
			}
			_, err = hconn.Write([]byte(msg))
			if err != nil {
				if err == io.EOF {
					t.logger.Error("connection closed by server", zap.Error(err))
					break
				}
				t.logger.Error("failed to write telnet message", zap.Error(err))
				break
			}
			if msg == "^C" {
				break
			}
			if len(strings.Trim(msg, " ")) > 0 {
				t.logger.Info(fmt.Sprintf("Sending: %d bytes(s) to Server, Bytes:\n %s", len(string(msg)), string(msg)))
			}
		}
	}()

	return nil
}
