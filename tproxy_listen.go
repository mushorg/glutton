//go:build linux

package glutton

import (
	"fmt"
	"net"
	"syscall"
)

// listenTProxyTCP creates a TCP listener with IP_TRANSPARENT set.
// This replaces tproxy.ListenTCP, which returns (nil, nil) when setting
// socket options fails (it returns the wrong error variable).
//
// Only IP_TRANSPARENT is required for TCP: the original destination is
// exposed via Conn.LocalAddr() after accept. IP_RECVORIGDSTADDR is a UDP
// cmsg option and returns EOPNOTSUPP on many kernels (including WSL2).
func listenTProxyTCP(network string, laddr *net.TCPAddr) (net.Listener, error) {
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	fileDescriptorSource, err := listener.File()
	if err != nil {
		listener.Close()
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("get file descriptor: %w", err)}
	}
	defer fileDescriptorSource.Close()

	fd := int(fileDescriptorSource.Fd())
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		listener.Close()
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %w", err)}
	}

	return listener, nil
}

// dialTProxyUDP opens a UDP socket bound to laddr, which need not be a
// local address (IP_TRANSPARENT), and connected to raddr, so a reply leaves
// from the address the packet was sent to. SO_REUSEADDR lets replies to
// several sources leave from the same address at once. This replaces tproxy.DialUDP, which leaks the
// socket when bind or connect fails; the dialer closes it on any error.
func dialTProxyUDP(laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	dialer := net.Dialer{
		LocalAddr: laddr,
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					sockErr = fmt.Errorf("set socket option: SO_REUSEADDR: %w", err)
					return
				}
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
					sockErr = fmt.Errorf("set socket option: IP_TRANSPARENT: %w", err)
				}
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}
	conn, err := dialer.Dial("udp4", raddr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
