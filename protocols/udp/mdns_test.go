package udp

import (
	"context"
	"encoding/base64"
	"net"
	"testing"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func mdnsServicesBrowse() []byte {
	// PTR _services._dns-sd._udp.local (captured scanner probe)
	raw, err := base64.StdEncoding.DecodeString("AAAAAAABAAAAAAAACV9zZXJ2aWNlcwdfZG5zLXNkBF91ZHAFbG9jYWwAAAwAAQ==")
	if err != nil {
		panic(err)
	}
	return raw
}

func TestHandleMDNSServicesBrowse(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 49246}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5353}
	payload := mdnsServicesBrowse()

	err := HandleMDNS(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "mdns", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedMDNS)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, payload, events[0].Payload)
	require.Len(t, events[0].Questions, 1)
	require.Equal(t, "_services._dns-sd._udp.local", events[0].Questions[0].QName)
	require.Equal(t, uint16(12), events[0].Questions[0].QType)
	require.Equal(t, "PTR", events[0].Questions[0].QTypeName)
	require.Equal(t, uint16(1), events[0].Questions[0].QClass)
}

func TestHandleMDNSShortHeader(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5353}
	payload := []byte{0x00, 0x01, 0x00, 0x00}

	err := HandleMDNS(context.Background(), src, dst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "mdns", h.produced[0].handler)
	require.Empty(t, h.replies)

	events, ok := h.produced[0].decoded.([]parsedMDNS)
	require.True(t, ok)
	require.Len(t, events, 1)
	require.Empty(t, events[0].Questions)
	require.Equal(t, payload, events[0].Payload)
}

func TestHandleMDNSEmptyPayload(t *testing.T) {
	h := &recordingHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 5353}

	err := HandleMDNS(context.Background(), src, dst, nil, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "mdns", h.produced[0].handler)
	require.Empty(t, h.replies)
}

func TestParseMDNSQuestionsCompressedName(t *testing.T) {
	// Two questions; second QNAME is a compression pointer to offset 12 (first name).
	// Header qdcount=2, then: 03www07example03com00 TYPE A CLASS IN
	// then: C0 0c TYPE AAAA CLASS IN
	msg := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
		0xc0, 0x0c,
		0x00, 0x1c, 0x00, 0x01,
	}
	questions, err := parseMDNSQuestions(msg)
	require.NoError(t, err)
	require.Len(t, questions, 2)
	require.Equal(t, "www.example.com", questions[0].QName)
	require.Equal(t, "A", questions[0].QTypeName)
	require.Equal(t, "www.example.com", questions[1].QName)
	require.Equal(t, "AAAA", questions[1].QTypeName)
}

func TestParseMDNSQuestionsTruncatedQuestion(t *testing.T) {
	msg := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'a', 'b', 'c', 0x00,
		0x00, 0x01, // missing class
	}
	questions, err := parseMDNSQuestions(msg)
	require.Error(t, err)
	require.Empty(t, questions)
}
