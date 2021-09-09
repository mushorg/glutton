package glutton

import (
	"context"
	"fmt"
	"net"
	"time"
)

// closeOnShutdown close all connections before system shutdown
func (g *Glutton) closeOnShutdown(conn net.Conn, done <-chan struct{}) {
	select {
	case <-g.ctx.Done():
		if err := conn.Close(); err != nil {
			g.Logger.Error(fmt.Sprintf("[glutton  ]  error on ctx close: %v", err))
		}
		return
	case <-done:
		if err := conn.Close(); err != nil {
			g.Logger.Debug(fmt.Sprintf("[glutton  ]  error on handler close: %v", err))
		}
		return
	}
}

type contextKey string

// Drive child context from parent context with additional value required for sepcific handler
func (g *Glutton) contextWithTimeout(timeInSeconds int) context.Context {
	return context.WithValue(g.ctx, contextKey("timeout"), time.Duration(timeInSeconds)*time.Second)
}

// UpdateConnectionTimeout increase connection timeout limit on connection I/O operation
func (g *Glutton) UpdateConnectionTimeout(ctx context.Context, conn net.Conn) {
	if timeout, ok := ctx.Value("timeout").(time.Duration); ok {
		conn.SetDeadline(time.Now().Add(timeout))
	}
}
