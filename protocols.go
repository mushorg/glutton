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

	g.protocolHandlers["smtp"] = func(conn net.Conn) (err error) {
		done := make(chan struct{})
		go g.closeOnShutdown(conn, done)
		ctx := g.withTimeout(72) // context with timeout
		err = g.HandleSMTP(ctx, conn)
		done <- struct{}{}
		return err
	}
	g.protocolHandlers["rdp"] = func(conn net.Conn) (err error) {
		done := make(chan struct{})
		go g.closeOnShutdown(conn, done)
		ctx := g.withTimeout(72) // context with timeout
		err = g.HandleRDP(ctx, conn)
		done <- struct{}{}
		return err
	}
	g.protocolHandlers["smb"] = func(conn net.Conn) (err error) {
		done := make(chan struct{})
		go g.closeOnShutdown(conn, done)
		ctx := g.withTimeout(72) // context with timeout
		err = g.HandleSMB(ctx, conn)
		done <- struct{}{}
		return err
	}
	g.protocolHandlers["ftp"] = func(conn net.Conn) (err error) {
		done := make(chan struct{})
		go g.closeOnShutdown(conn, done)
		ctx := g.withTimeout(72) // context with timeout
		err = g.HandleFTP(ctx, conn)
		done <- struct{}{}
		return err
	}
	g.protocolHandlers["sip"] = func(conn net.Conn) (err error) {
		done := make(chan struct{})
		go g.closeOnShutdown(conn, done)
		err = g.HandleSIP(g.ctx, conn)
		done <- struct{}{}
		return err
	}
	g.protocolHandlers["rfb"] = func(conn net.Conn) (err error) {
		done := make(chan struct{})
		go g.closeOnShutdown(conn, done)
		err = g.HandleRFB(g.ctx, conn)
		done <- struct{}{}
		return err
	}
	g.protocolHandlers["telnet"] = func(conn net.Conn) (err error) {
		done := make(chan struct{})
		go g.closeOnShutdown(conn, done)
		ctx := g.withTimeout(72) // context with timeout
		err = g.HandleTelnet(ctx, conn)
		done <- struct{}{}
		return err
	}
	g.protocolHandlers["proxy_ssh"] = func(conn net.Conn) (err error) {
		done := make(chan struct{})
		go g.closeOnShutdown(conn, done)
		ctx := g.withTimeout(72) // context with timeout
		err = g.sshProxy.handle(ctx, conn)
		done <- struct{}{}
		return err
	}
	g.protocolHandlers["default"] = func(conn net.Conn) (err error) {
		done := make(chan struct{})
		go g.closeOnShutdown(conn, done)
		snip, bufConn, err := g.Peek(conn, 4)
		g.onErrorClose(err, conn)
		httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true}
		if _, ok := httpMap[strings.ToUpper(string(snip))]; ok == true {
			err = g.HandleHTTP(g.ctx, bufConn)
		} else {
			err = g.HandleTCP(g.ctx, bufConn)
		}
		done <- struct{}{}
		return err
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
func (g *Glutton) withTimeout(timeInSeconds uint8) context.Context {
	limit := time.Duration(timeInSeconds) * time.Second
	return context.WithValue(g.ctx, "timeout", time.Now().Add(limit))
}

// updateIdleTime increase connection timeout limit on connection I/O operation
func (g *Glutton) updateIdleTime(ctx context.Context, conn net.Conn) {
	if timeout, ok := ctx.Value("timeout").(time.Time); ok {
		conn.SetDeadline(timeout)
	}
}
