//go:build linux

package ipopts

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// ipv4Packet builds an IPv4 header with the given options and protocol,
// followed by a 20-byte transport header.
func ipv4Packet(proto byte, opts []byte) []byte {
	ihl := 20 + len(opts)
	p := make([]byte, ihl+20)
	p[0] = 0x40 | byte(ihl/4)
	p[2], p[3] = byte(len(p)>>8), byte(len(p))
	p[8] = 64
	p[9] = proto
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[16:20], []byte{192, 0, 2, 10})
	copy(p[20:], opts)
	return p
}

func TestCaptureFilter(t *testing.T) {
	vm, err := bpf.NewVM(filter(256))
	require.NoError(t, err)

	ipv6 := make([]byte, 60)
	ipv6[0] = 0x60
	ipv6[6] = 6
	for name, tc := range map[string]struct {
		pkt  []byte
		want bool
	}{
		"tcp with options":    {ipv4Packet(6, []byte{1, 1, 1, 0}), true},
		"tcp with 40 bytes":   {ipv4Packet(6, make([]byte, 40)), true},
		"tcp without options": {ipv4Packet(6, nil), false},
		"udp with options":    {ipv4Packet(17, []byte{1, 1, 1, 0}), false},
		"ipv6 tcp":            {ipv6, false},
		"bad ihl":             {append([]byte{0x44}, ipv4Packet(6, nil)[1:]...), false},
	} {
		n, err := vm.Run(tc.pkt)
		require.NoError(t, err, name)
		require.Equal(t, tc.want, n > 0, name)
	}
}

func TestOpenCaptureErrors(t *testing.T) {
	_, err := OpenCapture("lo", 0)
	require.ErrorContains(t, err, "invalid snaplen")
	_, err = OpenCapture("glutton-no-such-if0", 256)
	require.Error(t, err)
}

// TestCaptureLoopback sends a SYN with IP options over loopback and reads it
// back. It needs CAP_NET_RAW and skips without it.
func TestCaptureLoopback(t *testing.T) {
	c, err := OpenCapture("lo", 256)
	if errors.Is(err, unix.EPERM) {
		t.Skip("needs CAP_NET_RAW")
	}
	require.NoError(t, err)
	defer c.Close()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	d := net.Dialer{Timeout: 2 * time.Second, Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.IPPROTO_IP, unix.IP_OPTIONS, string([]byte{1, 1, 1, 0}))
		})
		if err != nil {
			return err
		}
		return serr
	}}
	go func() {
		if conn, err := d.Dial("tcp4", ln.Addr().String()); err == nil {
			conn.Close()
		}
	}()

	got := make(chan *Packet, 1)
	go func() {
		for {
			data, outgoing, err := c.ReadPacket()
			if err != nil {
				return
			}
			if pkt, ok := DecodeIPv4(data); ok && !outgoing && int(pkt.DstPort) == port {
				got <- pkt
				return
			}
		}
	}()
	select {
	case pkt := <-got:
		require.Equal(t, "SYN", pkt.Frame.Command)
		require.NotEmpty(t, pkt.Frame.Options)
		require.Equal(t, "127.0.0.1", pkt.SrcIP.String())
	case <-time.After(3 * time.Second):
		t.Fatal("no packet with IP options captured")
	}
}

// TestCaptureCloseUnblocksRead checks that Close ends a blocked ReadPacket.
func TestCaptureCloseUnblocksRead(t *testing.T) {
	c, err := OpenCapture("lo", 256)
	if errors.Is(err, unix.EPERM) {
		t.Skip("needs CAP_NET_RAW")
	}
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		for {
			if _, _, err := c.ReadPacket(); err != nil {
				done <- err
				return
			}
		}
	}()
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, c.Close())
	select {
	case err := <-done:
		require.ErrorIs(t, err, os.ErrClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket still blocked after Close")
	}
}
