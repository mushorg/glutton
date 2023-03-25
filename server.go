package glutton

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

type Server struct {
	lc   net.ListenConfig
	ln   net.Listener
	port uint
}

func InitServer(port uint) *Server {
	s := &Server{
		port: port,
	}
	s.lc = net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			var operr error
			if err := conn.Control(func(fd uintptr) {
				operr = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			if operr != nil {
				return operr
			}
			if err := conn.Control(func(fd uintptr) {
				operr = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.IP_TRANSPARENT, 1)
			}); err != nil {
				return err
			}
			return operr
		},
	}
	return s
}

func (s *Server) Start(ctx context.Context) error {
	var err error
	s.ln, err = s.lc.Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	return err
}

func (s *Server) Shutdown() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}
