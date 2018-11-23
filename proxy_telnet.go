package glutton

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/reiver/go-telnet"
	log "go.uber.org/zap"
)

//telnetProxy Struct
type telnetProxy struct {
	logger      *log.Logger
	curConn     net.Conn
	proxyclient *telnet.Client
	hostconn    *telnet.Conn
	glutton     *Glutton
	host        string
}

//NewTelnetProxy Create a new Telnet Proxy Session
func (g *Glutton) NewTelnetProxy(destinationURL string) (err error) {

	t := &telnetProxy{
		logger:  g.logger,
		glutton: g,
	}

	dest, err := url.Parse(destinationURL)
	if err != nil {
		t.logger.Error("[telnet.prxy] failed to parse destination address, check config.yaml")
		return err
	}
	t.logger.Info(fmt.Sprintf("[telnet proxy] %v", dest.Host))
	t.host = dest.Host
	g.telnetProxy = t
	return
}

//handle Telnet Proxy handler
func (t *telnetProxy) handle(ctx context.Context, conn net.Conn) (err error) {
	ended := false
	g := t.glutton
	tcpAddr, err := net.ResolveTCPAddr("tcp", t.host)
	if err != nil {
		t.logger.Error(fmt.Sprintf("ResolveTCPAddr failed: %v", err.Error()))
		return
	}
	hconn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		t.logger.Error(fmt.Sprintf("[telnet proxy  ]  Connection error: %v", err))
		return
	}
	go func() {
		defer func() {
			ended = true
			conn.Close()
			hconn.Close()
		}()
		for {
			g.updateConnectionTimeout(ctx, conn)
			if ended == true || hconn == nil || conn == nil {
				break
			}
			reply := make([]byte, 8*1024)
			if _, err = hconn.Read(reply); err != nil {
				if err == io.EOF {
					t.logger.Error(fmt.Sprintf("[telnet proxy  ]   Connection closed by Server"))
					break
				}
				t.logger.Error(fmt.Sprintf("[telnet proxy  ]   error: %v", err))
				break
			}

			t.logger.Info(fmt.Sprintf("[telnet proxy  ]   Info: Recieved: %d bytes(s) from Server. Bytes: %s", len(string(reply)), string(reply)))
			err = writeMsg(conn, string(reply), g)
			if err != nil {
				t.logger.Error(fmt.Sprintf("[telnet proxy] Error: %v", err))
				break
			}
		}
		return
	}()
	go func() {
		defer func() {
			ended = true
			conn.Close()
			hconn.Close()
		}()
		for {
			if ended == true || hconn == nil || conn == nil {
				return
			}
			msg, err := readMsg(conn, g)
			if err != nil {
				t.logger.Error(fmt.Sprintf("[telnet proxy] Error: %v", err))
				break
			}
			_, err = hconn.Write([]byte(msg))
			if err != nil {
				if err == io.EOF {
					t.logger.Error(fmt.Sprintf("[telnet proxy  ]   Connection closed by Server"))
					break
				}
				t.logger.Error(fmt.Sprintf("[telnet proxy  ]   Error: %v", err))
				break
			}
			if msg == "^C" {
				break
			}
			if len(strings.Trim(msg, " ")) > 0 {
				t.logger.Info(fmt.Sprintf("[telnet proxy  ]   Info: Sending: %d bytes(s) to Server, Bytes:\n %s", len(string(msg)), string(msg)))
			}
		}
		return
	}()

	return
}
