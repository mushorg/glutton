package glutton

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// mapProtocolHandlers map protocol handlers to corresponding protocol
func (g *Glutton) mapProtocolHandlers() {

	g.protocolHandlers["smtp"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.HandleSMTP(ctx, conn)
	}

	g.protocolHandlers["rdp"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.HandleRDP(ctx, conn)
	}

	g.protocolHandlers["smb"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.HandleSMB(ctx, conn)
	}

	g.protocolHandlers["ftp"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.HandleFTP(ctx, conn)
	}

	g.protocolHandlers["sip"] = func(ctx context.Context, conn net.Conn) (err error) {
		// TODO: remove 'context.TODO()' when handler code start using context.
		ctx = context.TODO()
		return g.HandleSIP(ctx, conn)
	}

	g.protocolHandlers["rfb"] = func(ctx context.Context, conn net.Conn) (err error) {
		// TODO: remove 'context.TODO()' when handler code start using context.
		ctx = context.TODO()
		return g.HandleRFB(ctx, conn)
	}

	g.protocolHandlers["proxy_tcp"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.tcpProxy(ctx, conn)
	}

	g.protocolHandlers["telnet"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.HandleTelnet(ctx, conn)
	}

	g.protocolHandlers["proxy_ssh"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.sshProxy.handle(ctx, conn)
	}

	g.protocolHandlers["jabber"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.HandleJabber(ctx, conn)
	}

	g.protocolHandlers["default"] = func(ctx context.Context, conn net.Conn) (err error) {
		// TODO: remove 'context.TODO()' when handler code start using context.
		ctx = context.TODO()
		snip, bufConn, err := g.Peek(conn, 4)
		g.onErrorClose(err, conn)
		httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true}
		if _, ok := httpMap[strings.ToUpper(string(snip))]; ok == true {
			return g.HandleHTTP(ctx, bufConn)
		}
		return g.HandleTCP(ctx, bufConn)
	}
}

// closeOnShutdown close all connections before system shutdown
func (g *Glutton) closeOnShutdown(conn net.Conn, done <-chan struct{}) {
	select {
	case <-g.ctx.Done():
		if err := conn.Close(); err != nil {
			g.logger.Error(fmt.Sprintf("[glutton  ]  error: %v", err))
		}
		return
	case <-done:
		return
	}
}

// Drive child context from parent context with additional value required for sepcific handler
func (g *Glutton) contextWithTimeout(timeInSeconds uint8) context.Context {
	limit := time.Duration(timeInSeconds) * time.Second
	return context.WithValue(g.ctx, "timeout", time.Now().Add(limit))
}

// updateConnectionTimeout increase connection timeout limit on connection I/O operation
func (g *Glutton) updateConnectionTimeout(ctx context.Context, conn net.Conn) {
	if timeout, ok := ctx.Value("timeout").(time.Time); ok {
		conn.SetDeadline(timeout)
	}
}
