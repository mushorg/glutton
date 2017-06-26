package glutton

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	proxy "github.com/mushorg/glutton/proxy_http"
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

	g.protocolHandlers["telnet"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.HandleTelnet(ctx, conn)
	}

	g.protocolHandlers["proxy_ssh"] = func(ctx context.Context, conn net.Conn) (err error) {
		return g.sshProxy.handle(ctx, conn)
	}

	g.protocolHandlers["default"] = func(ctx context.Context, conn net.Conn) (err error) {
		// TODO: remove 'context.TODO()' when handler code start using context.
		ctx = context.TODO()
		snip, bufConn, err := g.Peek(conn, 4)
		g.onErrorClose(err, conn)
		httpMap := map[string]bool{"GET ": true, "POST": true, "HEAD": true, "OPTI": true}
		if _, ok := httpMap[strings.ToUpper(string(snip))]; ok == true {
			return g.HandleHTTP(ctx, bufConn)
		} else {
			return g.HandleTCP(ctx, bufConn)
		}
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

func (g *Glutton) startHTTPProxy() {
	// Is SSL enabled?
	var sslEnabled = g.conf.GetBool("enableSSL")

	// User requested SSL mode.
	if sslEnabled {
		os.Setenv(proxy.EnvSSLCert, g.conf.GetString("certPath"))
		os.Setenv(proxy.EnvSSLKey, g.conf.GetString("keyPath"))
	}

	// Creating proxy.
	p := proxy.NewProxy()

	// Attaching logger.
	p.AddLogger(g.logger)

	// Attaching capture tool.
	res := make(chan proxy.Response, 256)

	p.AddBodyWriteCloser(proxy.New(res))

	// Saving captured data with a goroutine.
	go func() {
		for {
			select {
			case r := <-res:
				go func() {
					// log.Printf(`Captured Object:
					// ID: %v
					// Origin: %v
					// Method: %v
					// Status: %v
					// ContentType: %v
					// ContentLength: %v
					// Host: %v
					// URL: %v
					// Scheme: %v
					// Path: %v
					// Header: %v
					// Body: %v
					// RequestHeader: %v
					// RequestBody: %v
					// DateStart: %v
					// DateEnd: %v
					// TimeTaken: %v
					// `, r.ID, r.Origin, r.Method, r.Status, r.ContentType, r.ContentLength,
					// 	r.Host, r.Scheme, r.Path, r.Header, r.Body, r.RequestHeader, r.RequestBody,
					// 	r.DateStart, r.DateEnd, r.TimeTaken)
					g.logger.Info(fmt.Sprintf("[http.prxy] %q", r))
				}()
			}
		}
	}()

	bindAddress := g.conf.GetString("address")
	port := g.conf.GetInt("httpPort")
	targetAddress := g.conf.GetString("targetAddress")

	done := make(chan struct{})
	go func() {
		if err := p.Start(fmt.Sprintf("%s:%d", bindAddress, port), targetAddress); err != nil {
			g.logger.Error(fmt.Sprintf("[http.prxy] Failed to bind on the given interface (HTTP): %q", err))
		}
		g.logger.Info("[http.prxy] HTTP server stopped...")
	}()

	if sslEnabled {
		go func() {
			sslPort := g.conf.GetInt("sslPort")
			g.logger.Info(fmt.Sprintf("[***********] httpS  started %s:%d", bindAddress, sslPort))
			if err := p.StartTLS(fmt.Sprintf("%s:%d", bindAddress, sslPort)); err != nil {
				g.logger.Error(fmt.Sprintf("[http.prxy] Failed to bind on the given interface (HTTPS): %q", err))
			}
			g.logger.Info("[http.prxy] HTTPS server stopped...")
		}()
	}

	closed := 0
	for {
		select {
		case <-done:
			closed++
			if closed == 2 {
				return
			}
		case <-g.ctx.Done():
			g.logger.Info("[http.prxy] http proxy service stopped successfully.")
			return
		}
	}

}
