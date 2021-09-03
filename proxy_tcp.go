package glutton

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/kung-foo/freki"
)

const dialTimeout = 120 * time.Second

func (g *Glutton) tcpProxy(ctx context.Context, conn net.Conn) (err error) {
	defer func() {
		err = conn.Close()
		if err != nil {
			g.Logger.Error(fmt.Sprintf("[tcp.prxy] error: %v", err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	ck := freki.NewConnKeyByString(host, port)
	md := g.Processor.Connections.GetByFlow(ck)
	if md == nil {
		g.Logger.Warn(fmt.Sprintf("[tcp.prxy] untracked connection: %s", conn.RemoteAddr().String()))
		return
	}

	target := md.Rule.Target

	fmt.Printf("Rule Traget: %+v\n", target)

	dest, err := url.Parse(target)
	if err != nil {
		g.Logger.Error("[tcp.prxy]failed to parse destination address, check rules file")
		return err
	}

	if dest.Scheme != "tcp" && dest.Scheme != "docker" {
		g.Logger.Error(fmt.Sprintf("[tcp.prxy] unsuppported scheme: %s", dest.Scheme))
		return
	}

	g.Logger.Info(fmt.Sprintf("[prxy.tcp] %s -> %v to %s", host, md.TargetPort, dest.String()))

	proxyConn, err := net.DialTimeout("tcp", dest.Host, dialTimeout)

	if err != nil {
		g.Logger.Error(fmt.Sprintf("[prxy.tcp] %v", err))
		return err
	}

	// TODO: Log traffic by wrapping connection with io.ReadClose
	go func() {
		_, err = io.Copy(proxyConn, conn)
		if err != nil {
			g.Logger.Error(fmt.Sprintf("[prxy.tcp] %v", err))
		}
	}()

	_, err = io.Copy(conn, proxyConn)
	if err != nil {
		g.Logger.Error(fmt.Sprintf("[prxy.tcp] %v", err))
	}

	return err
}
