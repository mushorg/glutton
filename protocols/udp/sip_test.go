package udp

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

type producedUDP struct {
	handler string
	payload []byte
	decoded interface{}
}

type recordingHoneypot struct {
	mu       sync.Mutex
	produced []producedUDP
	replies  [][]byte
}

func (h *recordingHoneypot) ProduceTCP(string, net.Conn, connection.Metadata, []byte, interface{}) error {
	return nil
}

func (h *recordingHoneypot) ProduceUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.produced = append(h.produced, producedUDP{handler: handler, payload: append([]byte(nil), payload...), decoded: decoded})
	return nil
}

func (h *recordingHoneypot) ReplyUDP(srcAddr, dstAddr *net.UDPAddr, payload []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.replies = append(h.replies, append([]byte(nil), payload...))
	return nil
}

func (h *recordingHoneypot) ConnectionByFlow([2]uint64) connection.Metadata {
	return connection.Metadata{}
}
func (h *recordingHoneypot) UpdateConnectionTimeout(context.Context, net.Conn) error {
	return nil
}
func (h *recordingHoneypot) MetadataByConnection(net.Conn) (connection.Metadata, error) {
	return connection.Metadata{}, nil
}

type testLogger struct{}

func (testLogger) Debug(string, ...any) {}
func (testLogger) Info(string, ...any)  {}
func (testLogger) Warn(string, ...any)  {}
func (testLogger) Error(string, ...any) {}

func sipOptions() []byte {
	return []byte("OPTIONS sip:100@1.2.3.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 203.0.113.10:5079;branch=z9hG4bK-1;rport\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: \"sipvicious\"<sip:100@1.1.1.1>\r\n" +
		"From: \"sipvicious\"<sip:100@1.1.1.1>;tag=abc\r\n" +
		"User-Agent: friendly-scanner\r\n" +
		"Call-ID: 12345\r\n" +
		"Contact: sip:100@203.0.113.10:5079\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Accept: application/sdp\r\n" +
		"Content-Length: 0\r\n\r\n")
}

func TestHandleSIPOptions(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5060}

	err := HandleSIP(context.Background(), src, dst, sipOptions(), connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)

	require.Len(t, h.produced, 1)
	require.Equal(t, "sip", h.produced[0].handler)
	require.True(t, strings.HasPrefix(string(h.produced[0].payload), "OPTIONS "))

	events, ok := h.produced[0].decoded.([]parsedSIP)
	require.True(t, ok)
	require.Len(t, events, 2)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, "write", events[1].Direction)
	require.Contains(t, string(events[1].Payload), "SIP/2.0 200")

	require.Len(t, h.replies, 1)
	require.Contains(t, string(h.replies[0]), "SIP/2.0 200")
}

func TestHandleSIPRegisterNoReply(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5060}
	req := []byte("REGISTER sip:1.2.3.4 SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP 203.0.113.10:5079;branch=z9hG4bK-2\r\n" +
		"From: <sip:a@1.2.3.4>;tag=1\r\n" +
		"To: <sip:a@1.2.3.4>\r\n" +
		"Call-ID: 99\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sip:a@203.0.113.10:5079>\r\n" +
		"Content-Length: 0\r\n\r\n")

	err := HandleSIP(context.Background(), src, dst, req, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.replies, 0)
	require.Len(t, h.produced, 1)
	events, ok := h.produced[0].decoded.([]parsedSIP)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
}

func TestHandleSIPMalformedStillProduces(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5060}

	err := HandleSIP(context.Background(), src, dst, []byte("not-sip"), connection.Metadata{}, testLogger{}, h)
	require.Error(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "sip", h.produced[0].handler)
	events, ok := h.produced[0].decoded.([]parsedSIP)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, []byte("not-sip"), events[0].Payload)
}

func TestHandleSIPEmptyPayload(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5079}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5060}

	err := HandleSIP(context.Background(), src, dst, nil, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Empty(t, h.replies)
}
