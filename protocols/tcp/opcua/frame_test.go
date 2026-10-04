package opcua

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/gopcua/opcua/uacp"
	"github.com/stretchr/testify/require"
)

func TestParseHello(t *testing.T) {
	payload, err := EncodeHello("opc.tcp://203.0.113.10:4840")
	require.NoError(t, err)
	f := Parse(payload)
	require.Equal(t, "HEL", f.MessageType)
	require.Equal(t, "Hello", f.Service)
	require.Equal(t, "opc.tcp://203.0.113.10:4840", f.EndpointURL)
	require.Equal(t, payload, f.Payload)
}

func TestSessionHelloACK(t *testing.T) {
	hel, err := EncodeHello("opc.tcp://1.2.3.4:4840")
	require.NoError(t, err)
	reply, err := NewSession("opc.tcp://1.2.3.4:4840").Reply(hel)
	require.NoError(t, err)
	f := Parse(reply)
	require.Equal(t, "ACK", f.MessageType)
	require.Equal(t, "Acknowledge", f.Service)
}

func TestSessionReverseHelloDoesNotDial(t *testing.T) {
	rhe, err := EncodeReverseHello("opc.tcp://203.0.113.99:4840", "opc.tcp://1.2.3.4:4840")
	require.NoError(t, err)
	f := Parse(rhe)
	require.Equal(t, "RHE", f.MessageType)
	require.Equal(t, "ReverseHello", f.Service)

	reply, err := NewSession("opc.tcp://1.2.3.4:4840").Reply(rhe)
	require.NoError(t, err)
	errf := Parse(reply)
	require.Equal(t, "ERR", errf.MessageType)
	require.Equal(t, "Error", errf.Service)
}

func TestReadMessageRejectsOversizeWithoutBodyRead(t *testing.T) {
	hdr := uacp.Header{MessageType: "HEL", ChunkType: 'F', MessageSize: MaxMessageSize + 1}
	raw, err := hdr.Encode()
	require.NoError(t, err)
	// leftover body bytes must remain unread
	leftover := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	r := bytes.NewReader(append(raw, leftover...))
	_, err = ReadMessage(r)
	require.Error(t, err)
	rest, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, leftover, rest)
}

func TestReadMessageTruncatedHeader(t *testing.T) {
	_, err := ReadMessage(bytes.NewReader([]byte{'H', 'E', 'L'}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestEncodeUACPSize(t *testing.T) {
	body := []byte{1, 2, 3, 4}
	msg, err := EncodeUACP("ERR", 'F', body)
	require.NoError(t, err)
	require.Equal(t, uint32(HeaderLen+len(body)), binary.LittleEndian.Uint32(msg[4:8]))
}
