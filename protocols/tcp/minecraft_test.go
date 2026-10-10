package tcp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/minecraft"
	"github.com/stretchr/testify/require"
)

var mcAddr = "127.0.0.100000"

func mcHandshake(proto int32, state int32) []byte {
	body := minecraft.AppendVarInt(nil, proto)
	body = minecraft.AppendVarInt(body, int32(len(mcAddr)+1))
	body = append(body, mcAddr...)
	body = append(body, '0', 0x63, 0xdd)
	body = minecraft.AppendVarInt(body, state)
	return minecraft.BuildPacket(0, body)
}

func runMinecraft(t *testing.T, client func(c net.Conn)) (producedTCP, *recordingLogger) {
	t.Helper()
	srv, cli := net.Pipe()
	h := newFakeHoneypot()
	logger := &recordingLogger{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = HandleMinecraft(context.Background(), srv, connection.Metadata{}, logger, h)
	}()
	client(cli)
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return")
	}
	require.Len(t, h.produced, 1)
	return <-h.produced, logger
}

func TestMinecraftStatusPing(t *testing.T) {
	hs := mcHandshake(-1, 1)
	req := []byte{0x01, 0x00}
	ping := append([]byte{0x09, 0x01}, 1, 2, 3, 4, 5, 6, 7, 8)
	var status, pong []byte
	p, _ := runMinecraft(t, func(c net.Conn) {
		_, _ = c.Write(append(hs, req...))
		var err error
		status, err = readMCPacket(c)
		require.NoError(t, err)
		_, _ = c.Write(ping)
		pong, err = readMCPacket(c)
		require.NoError(t, err)
	})
	require.Equal(t, "minecraft", p.protocol)
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 5)
	require.Equal(t, "handshake", frames[0].Command)
	require.Equal(t, mcAddr+"0", frames[0].Path)
	require.Equal(t, int32(-1), *frames[0].ProtocolVersion)
	require.Equal(t, uint16(25565), frames[0].Port)
	require.Equal(t, "status_request", frames[1].Command)
	require.Equal(t, "status_response", frames[2].Status)
	require.Equal(t, status, frames[2].Payload)
	require.Contains(t, string(status), `"protocol":769`)
	require.Equal(t, "ping", frames[3].Command)
	require.Equal(t, "pong", frames[4].Status)
	require.Equal(t, pong, frames[4].Payload)
}

func TestMinecraftLogin(t *testing.T) {
	login := minecraft.BuildPacket(0, append([]byte{3}, "bob"...))
	p, _ := runMinecraft(t, func(c net.Conn) {
		_, _ = c.Write(append(mcHandshake(767, 2), login...))
		_, err := readMCPacket(c)
		require.NoError(t, err)
	})
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 3)
	require.Equal(t, "login_start", frames[1].Command)
	require.Equal(t, "bob", frames[1].Username)
	require.Equal(t, "disconnect", frames[2].Status)
}

func TestMinecraftEarlyDisconnect(t *testing.T) {
	// Declared string length exceeds the bytes that arrive.
	raw := mcHandshake(-1, 1)[:12]
	p, logger := runMinecraft(t, func(c net.Conn) { _, _ = c.Write(raw) })
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 1)
	require.Equal(t, "malformed", frames[0].Command)
	require.True(t, frames[0].Truncated)
	require.Equal(t, raw, frames[0].Payload)
	require.Empty(t, logger.errs)
}

func TestMinecraftNoData(t *testing.T) {
	p, _ := runMinecraft(t, func(c net.Conn) {})
	require.Empty(t, p.decoded.([]parsedMinecraft))
}

func TestMinecraftOversize(t *testing.T) {
	p, _ := runMinecraft(t, func(c net.Conn) {
		_, _ = c.Write(minecraft.AppendVarInt(nil, minecraft.MaxPacketLen+1))
	})
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 1)
	require.Equal(t, "malformed", frames[0].Command)
}

func readMCPacket(c net.Conn) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	pkt, err := minecraft.ReadPacket(c)
	if err != nil {
		return nil, err
	}
	return pkt.Raw, nil
}
