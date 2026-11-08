//go:build linux

package ipopts

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Capture reads IPv4 TCP packets that carry IP options from one interface.
// It is an AF_PACKET datagram socket bound to ETH_P_IP, so every read starts
// at the IPv4 header whatever the link type, and a kernel BPF filter drops
// everything else. The kernel does not hand outgoing packets to a socket
// bound to one protocol, so only received packets arrive.
type Capture struct {
	f      *os.File
	buf    []byte
	closed atomic.Bool
}

// OpenCapture opens a capture on iface that keeps the first snaplen bytes
// of each packet. It needs CAP_NET_RAW.
func OpenCapture(iface string, snaplen int) (*Capture, error) {
	if snaplen <= 0 || snaplen > 65535 {
		return nil, fmt.Errorf("invalid snaplen %d", snaplen)
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	prog, err := bpf.Assemble(filter(uint32(snaplen)))
	if err != nil {
		return nil, err
	}

	// Protocol 0 receives nothing until bind, so no unfiltered packet from
	// another interface slips in before the filter is attached.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	sf := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		sf[i] = unix.SockFilter{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(sf)), Filter: &sf[0]}); err != nil {
		unix.Close(fd)
		return nil, os.NewSyscallError("setsockopt SO_ATTACH_FILTER", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: ifi.Index}); err != nil {
		unix.Close(fd)
		return nil, os.NewSyscallError("bind", err)
	}
	// A non-blocking fd joins the runtime poller, so Close unblocks a
	// pending ReadPacket.
	return &Capture{f: os.NewFile(uintptr(fd), "ipopts-capture"), buf: make([]byte, snaplen)}, nil
}

// ReadPacket blocks until the next packet and returns it from the IPv4
// header on, cut to snaplen. The slice is reused by the next call. outgoing
// reports a packet the host sent. After Close it returns os.ErrClosed.
func (c *Capture) ReadPacket() (data []byte, outgoing bool, err error) {
	data, outgoing, err = c.readPacket()
	if err != nil && c.closed.Load() {
		// A read that Close interrupts fails with the poller's own "use of
		// closed file" error, which does not wrap os.ErrClosed.
		return nil, false, os.ErrClosed
	}
	return data, outgoing, err
}

func (c *Capture) readPacket() (data []byte, outgoing bool, err error) {
	rc, err := c.f.SyscallConn()
	if err != nil {
		return nil, false, err
	}
	var (
		n    int
		from unix.Sockaddr
		rerr error
	)
	if err := rc.Read(func(fd uintptr) bool {
		n, from, rerr = unix.Recvfrom(int(fd), c.buf, 0)
		return !errors.Is(rerr, unix.EAGAIN) && !errors.Is(rerr, unix.EINTR)
	}); err != nil {
		return nil, false, err
	}
	if rerr != nil {
		return nil, false, os.NewSyscallError("recvfrom", rerr)
	}
	if ll, ok := from.(*unix.SockaddrLinklayer); ok {
		outgoing = ll.Pkttype == unix.PACKET_OUTGOING
	}
	return c.buf[:n], outgoing, nil
}

// Close stops the capture and unblocks a pending ReadPacket.
func (c *Capture) Close() error {
	c.closed.Store(true)
	return c.f.Close()
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// filter accepts IPv4 TCP packets whose header is longer than 20 bytes,
// i.e. that carry options (the old pcap filter "ip and tcp and (ip[0] &
// 0x0f) > 5"), keeping snaplen bytes. Offsets start at the IPv4 header.
func filter(snaplen uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 4},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 4, SkipTrue: 6}, // not IPv4
		bpf.LoadAbsolute{Off: 0, Size: 1},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0f},
		bpf.JumpIf{Cond: bpf.JumpLessOrEqual, Val: 5, SkipTrue: 3}, // IHL <= 5: no options
		bpf.LoadAbsolute{Off: 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: 1}, // not TCP
		bpf.RetConstant{Val: snaplen},
		bpf.RetConstant{Val: 0},
	}
}
