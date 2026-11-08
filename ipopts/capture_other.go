//go:build !linux

package ipopts

import "errors"

// Capture is only implemented on Linux.
type Capture struct{}

// OpenCapture always fails outside Linux.
func OpenCapture(iface string, snaplen int) (*Capture, error) {
	return nil, errors.New("ipopts capture requires Linux AF_PACKET sockets")
}

// ReadPacket is never reached outside Linux.
func (c *Capture) ReadPacket() ([]byte, bool, error) {
	return nil, false, errors.New("ipopts capture requires Linux AF_PACKET sockets")
}

// Close is a no-op outside Linux.
func (c *Capture) Close() error { return nil }
