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
