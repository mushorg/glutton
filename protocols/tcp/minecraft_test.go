package tcp

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/recall"
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
	return runMinecraftFrom(t, nil, client)
}

// runMinecraftFrom is runMinecraft with the server side reporting remote as
// its peer; nil keeps net.Pipe's address (no recall visit).
func runMinecraftFrom(t *testing.T, remote net.Addr, client func(c net.Conn)) (producedTCP, *recordingLogger) {
	t.Helper()
	pipe, cli := net.Pipe()
	var srv net.Conn = pipe
	if remote != nil {
		srv = connWithRemote{Conn: pipe, remote: remote}
	}
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

var mcLogin = minecraft.BuildPacket(0, append([]byte{3}, "bob"...))

func TestMinecraftLogin(t *testing.T) {
	var resp []byte
	p, _ := runMinecraft(t, func(c net.Conn) {
		_, _ = c.Write(append(mcHandshake(minecraft.DefaultProtocol, 2), mcLogin...))
		var err error
		resp, err = readMCPacket(c)
		require.NoError(t, err)
	})
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 3)
	require.Equal(t, "login_start", frames[1].Command)
	require.Equal(t, "bob", frames[1].Username)
	require.Equal(t, "not_whitelisted", frames[2].Status)
	require.Equal(t, minecraft.BuildLoginDisconnect(minecraft.ReasonNotWhitelisted), resp)
}

// A login Handshake with a foreign protocol (or a transfer) is rejected before
// Login Start, as vanilla does; a Login Start already in flight is recorded.
func TestMinecraftLoginRejected(t *testing.T) {
	for _, tc := range []struct {
		proto, state int32
		reason       string
	}{
		{767, minecraft.StateLogin, minecraft.ReasonIncompatible},
		{47, minecraft.StateLogin, minecraft.ReasonOutdatedClient},
		{minecraft.DefaultProtocol, minecraft.StateTransfer, minecraft.ReasonTransfersDisabled},
	} {
		var resp []byte
		p, _ := runMinecraft(t, func(c net.Conn) {
			// net.Pipe is unbuffered: write in the background and wait for
			// the in-flight Login Start to be consumed before closing.
			wrote := make(chan struct{})
			go func() {
				defer close(wrote)
				_, _ = c.Write(append(mcHandshake(tc.proto, tc.state), mcLogin...))
			}()
			var err error
			resp, err = readMCPacket(c)
			require.NoError(t, err)
			<-wrote
		})
		require.Equal(t, minecraft.BuildLoginDisconnect(tc.reason), resp)
		frames := p.decoded.([]parsedMinecraft)
		require.Len(t, frames, 3)
		require.Equal(t, "handshake", frames[0].Command)
		require.Equal(t, strings.TrimPrefix(tc.reason, "multiplayer.disconnect."), frames[1].Status)
		require.Equal(t, "login_start", frames[2].Command)
		require.Equal(t, "bob", frames[2].Username)
	}
}

func TestMinecraftLoginRejectedNoLoginStart(t *testing.T) {
	old := minecraftLingerWait
	minecraftLingerWait = 10 * time.Millisecond
	defer func() { minecraftLingerWait = old }()
	p, _ := runMinecraft(t, func(c net.Conn) {
		go func() { _, _ = c.Write(mcHandshake(47, minecraft.StateLogin)) }()
		_, err := readMCPacket(c)
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond)
	})
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 2)
	require.Equal(t, "outdated_client", frames[1].Status)
}

// matscan's probe (protocol 47) gets the 769 status, not an echo, and a second
// Status Request ends the session as on vanilla.
func TestMinecraftStatusNoEchoRepeat(t *testing.T) {
	var status []byte
	p, _ := runMinecraft(t, func(c net.Conn) {
		_, _ = c.Write(append(mcHandshake(47, 1), 0x01, 0x00))
		var err error
		status, err = readMCPacket(c)
		require.NoError(t, err)
		_, _ = c.Write([]byte{0x01, 0x00})
	})
	require.Equal(t, minecraft.BuildStatusResponse(minecraft.Personas[0]), status)
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 4)
	require.Equal(t, "status_request", frames[3].Command)
}

// A returning source gets the next persona after recall.visit_gap; within the
// gap it keeps its persona. The visit is noted with the handshake address.
func TestMinecraftRecallRotatesPersona(t *testing.T) {
	now := time.Date(2026, 10, 12, 21, 0, 0, 0, time.UTC)
	orig := minecraftRecall
	store := recall.NewWithClock(recall.Config{Enabled: true, Gap: time.Hour}, func() time.Time { return now })
	minecraftRecall = store
	t.Cleanup(func() { minecraftRecall = orig })

	// matscan's probe as captured (Ochi event c3b15a69-9c6f-4c36-89ac-07517a0380d2).
	probe := []byte{0x0d, 0x00, 0x2f, 0x07, 'm', 'a', 't', 's', 'c', 'a', 'n', 0x05, 0x39, 0x01, 0x01, 0x00}
	remote := staticAddr{"176.65.149.198:61000"}
	status := func() ([]byte, producedTCP, *recordingLogger) {
		var resp []byte
		p, logger := runMinecraftFrom(t, remote, func(c net.Conn) {
			_, _ = c.Write(probe)
			var err error
			resp, err = readMCPacket(c)
			require.NoError(t, err)
		})
		return resp, p, logger
	}

	for i, persona := range []minecraft.Persona{minecraft.Personas[0], minecraft.Personas[1], minecraft.Personas[2], minecraft.Personas[0]} {
		resp, p, logger := status()
		want := minecraft.BuildStatusResponse(persona)
		require.Equal(t, want, resp, "visit %d", i+1)
		require.Equal(t, probe[:14], p.payload)
		require.Equal(t, []parsedMinecraft{
			{Direction: "read", Command: "handshake", Path: "matscan", ProtocolVersion: ptrInt32(47), Port: 1337, NextState: 1, Payload: probe[:14]},
			{Direction: "read", Command: "status_request", Payload: probe[14:]},
			{Direction: "write", Status: "status_response", Variant: persona.Name, Visit: i + 1, Payload: want},
		}, p.decoded.([]parsedMinecraft), "visit %d", i+1)
		if i > 0 {
			require.Contains(t, logger.infos, "returning Minecraft source")
			require.True(t, logger.hasAttr("previous_variant", minecraft.Personas[(i-1)%len(minecraft.Personas)].Name))
		}

		// A second connection within the gap stays in the same visit.
		resp, _, _ = status()
		require.Equal(t, want, resp)

		now = now.Add(2 * time.Hour)
	}
	v := store.Begin("minecraft", net.ParseIP("176.65.149.198"), len(minecraft.Personas))
	require.Equal(t, []string{"handshake", "status_request"}, v.Previous.Commands)
	require.Equal(t, []string{"matscan"}, v.Previous.Paths)
	require.Equal(t, 2, v.Previous.Events)
}

func ptrInt32(v int32) *int32 { return &v }

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

func TestMinecraftLegacyPing(t *testing.T) {
	for name, raw := range map[string][]byte{
		"bare":          {0xfe, 0x01},
		"plugin_packet": {0xfe, 0x01, 0xfa, 0x00, 0x0b, 'M', 0, 'C', 0, '|', 0, 'P', 0, 'i', 0, 'n', 0, 'g', 0, 'H', 0, 'o', 0, 's', 0, 't'},
	} {
		t.Run(name, func(t *testing.T) {
			var reply []byte
			p, logger := runMinecraft(t, func(c net.Conn) {
				go func() { _, _ = c.Write(raw) }()
				reply = make([]byte, len(minecraft.BuildLegacyKick(minecraft.Personas[0])))
				_, err := io.ReadFull(c, reply)
				require.NoError(t, err)
			})
			require.Equal(t, "minecraft", p.protocol)
			require.Equal(t, raw, p.payload)
			frames := p.decoded.([]parsedMinecraft)
			require.Len(t, frames, 2)
			require.Equal(t, parsedMinecraft{Direction: "read", Command: "legacy_ping", Payload: raw}, frames[0])
			require.Equal(t, "write", frames[1].Direction)
			require.Equal(t, "legacy_status_response", frames[1].Status)
			require.Equal(t, reply, frames[1].Payload)
			require.Equal(t, minecraft.BuildLegacyKick(minecraft.Personas[0]), reply)
			require.Empty(t, logger.errs)
		})
	}
}

func TestMinecraftLegacyPingSingleByteIsMalformed(t *testing.T) {
	// a lone 0xFE is a truncated VarInt, not a ping: still recorded
	p, _ := runMinecraft(t, func(c net.Conn) { _, _ = c.Write([]byte{0xfe}) })
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 1)
	require.Equal(t, "malformed", frames[0].Command)
}
