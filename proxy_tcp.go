package glutton

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/kung-foo/freki"
	"go.uber.org/zap"
)

const dialTimeout = 120 * time.Second

func (g *Glutton) tcpProxy(ctx context.Context, conn net.Conn) error {
	defer func() {
		if err := conn.Close(); err != nil {
			g.Logger.Error("failed to close tcp proxy connection", zap.Error(err))
		}
	}()

	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	ck := freki.NewConnKeyByString(host, port)
	md := g.Processor.Connections.GetByFlow(ck)
	if md == nil {
		g.Logger.Warn("untracked tcp proxy connection", zap.String("remote_address", conn.RemoteAddr().String()))
		return nil
	}

	target := md.Rule.Target
	dest, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("failed to parse destination address, check rules file: %w", err)
	}

	if dest.Scheme != "tcp" && dest.Scheme != "docker" {
		return fmt.Errorf("unsuppported tcp proxy rule scheme: %s", dest.Scheme)
	}

	g.Logger.Info(fmt.Sprintf("proxy tcp: %s -> %v to %s", host, md.TargetPort, dest.String()))

	proxyConn, err := net.DialTimeout("tcp", dest.Host, dialTimeout)
	if err != nil {
		return fmt.Errorf("failed to dial tcp proxy destination: %w", err)
	}

	// TODO: Log traffic by wrapping connection with io.ReadClose
	go func() {
		_, err = io.Copy(proxyConn, conn)
		if err != nil {
			g.Logger.Error("faild to proxy", zap.Error(err))
		}
	}()

	_, err = io.Copy(conn, proxyConn)
	return err
}
