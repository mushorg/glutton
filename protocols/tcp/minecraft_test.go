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

// mcDragonLogin and mcDragonDisconnect are the Login Start and reply from
// Ochi event 291f9645-0f55-430e-ae74-226d391f19a9 (tcp/29421, protocol 769).
// Its Handshake was scrubbed by Ochi, so the test builds a fresh one.
var mcDragonLogin = []byte{
	0x1e, 0x00, 0x0c, 0x44, 0x72, 0x61, 0x67, 0x6f, 0x6e, 0x44, 0x69, 0x6d, 0x61, 0x34, 0x30, 0x3e,
	0xbd, 0xb2, 0xdc, 0x48, 0x2f, 0x37, 0xe1, 0x93, 0x19, 0x47, 0x63, 0xc2, 0x59, 0x07, 0xbc,
}

var mcDragonDisconnect = []byte{
	0x38, 0x00, 0x36, 0x7b, 0x22, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x6c, 0x61, 0x74, 0x65, 0x22, 0x3a,
	0x22, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x6c, 0x61, 0x79, 0x65, 0x72, 0x2e, 0x64, 0x69, 0x73,
	0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x2e, 0x6e, 0x6f, 0x74, 0x5f, 0x77, 0x68, 0x69, 0x74,
	0x65, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x64, 0x22, 0x7d,
}

func TestMinecraftLoginUUID(t *testing.T) {
	handshake := mcHandshake(minecraft.DefaultProtocol, minecraft.StateLogin)
	var resp []byte
	p, _ := runMinecraft(t, func(c net.Conn) {
		_, _ = c.Write(append(append([]byte{}, handshake...), mcDragonLogin...))
		var err error
		resp, err = readMCPacket(c)
		require.NoError(t, err)
	})
	require.Equal(t, mcDragonDisconnect, resp)
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 3)
	require.Equal(t, parsedMinecraft{
		Direction: "read", Command: "login_start", Username: "DragonDima40",
		UUID: "3ebdb2dc-482f-37e1-9319-4763c25907bc", Payload: mcDragonLogin,
	}, frames[1])
	require.Equal(t, parsedMinecraft{Direction: "write", Status: "not_whitelisted", Variant: "default", Visit: 1, Payload: mcDragonDisconnect}, frames[2])
}

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
	require.Equal(t, minecraft.BuildLoginDisconnect(minecraft.Personas[0], minecraft.ReasonNotWhitelisted), resp)
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
		require.Equal(t, minecraft.BuildLoginDisconnect(minecraft.Personas[0], tc.reason), resp)
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

// A returning source's login is checked against its persona's version: the
// smp persona (1.21.8, protocol 772) lets a 772 client log in and rejects a
// 769 client with its own version name.
func TestMinecraftRecallPersonaVersionGatesLogin(t *testing.T) {
	now := time.Date(2026, 11, 8, 10, 44, 0, 0, time.UTC)
	orig := minecraftRecall
	minecraftRecall = recall.NewWithClock(recall.Config{Enabled: true, Gap: time.Hour}, func() time.Time { return now })
	t.Cleanup(func() { minecraftRecall = orig })
	remote := staticAddr{"198.44.135.103:51524"}

	// Visit 1: default persona.
	_, _ = runMinecraftFrom(t, remote, func(c net.Conn) {
		_, _ = c.Write(append(mcHandshake(772, minecraft.StateStatus), 0x01, 0x00))
		_, err := readMCPacket(c)
		require.NoError(t, err)
	})
	now = now.Add(2 * time.Hour)

	smp := minecraft.Personas[1]
	var resp []byte
	p, _ := runMinecraftFrom(t, remote, func(c net.Conn) {
		_, _ = c.Write(append(mcHandshake(smp.Protocol, minecraft.StateLogin), mcLogin...))
		var err error
		resp, err = readMCPacket(c)
		require.NoError(t, err)
	})
	// smp is open: the login is accepted instead of not_whitelisted.
	require.Equal(t, minecraft.BuildLoginSuccess("bob"), resp)
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, 3)
	require.Equal(t, "bob", frames[1].Username)
	require.Equal(t, parsedMinecraft{Direction: "write", Status: "login_success", State: "login", Variant: "smp", Visit: 2, Payload: resp}, frames[2])

	// Same visit, a 1.21.4 client: incompatible, naming 1.21.8.
	p, _ = runMinecraftFrom(t, remote, func(c net.Conn) {
		go func() { _, _ = c.Write(mcHandshake(minecraft.DefaultProtocol, minecraft.StateLogin)) }()
		var err error
		resp, err = readMCPacket(c)
		require.NoError(t, err)
	})
	require.Equal(t, minecraft.BuildLoginDisconnect(smp, minecraft.ReasonIncompatible), resp)
	require.Contains(t, string(resp), `"with":["1.21.8"]`)
	frames = p.decoded.([]parsedMinecraft)
	require.Equal(t, "incompatible", frames[1].Status)
	require.Equal(t, "smp", frames[1].Variant)
	require.Equal(t, 2, frames[1].Visit)
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

// openMinecraftSource makes remote's next visit get the open smp persona and
// pins the session seams; it returns remote.
func openMinecraftSource(t *testing.T) net.Addr {
	t.Helper()
	now := time.Date(2026, 11, 8, 13, 0, 0, 0, time.UTC)
	origRecall, origWorld, origKA, origMax, origNow := minecraftRecall, minecraftWorld, minecraftKeepAliveEvery, minecraftSessionMax, minecraftNow
	minecraftRecall = recall.NewWithClock(recall.Config{Enabled: true, Gap: time.Hour}, func() time.Time { return now })
	minecraftWorld = minecraft.World{EntityID: 412, HashedSeed: 99, MaxPlayers: 10, X: 12, Y: 70, Z: -40}
	minecraftKeepAliveEvery = time.Hour
	minecraftSessionMax = time.Hour
	minecraftNow = func() time.Time { return now }
	t.Cleanup(func() {
		minecraftRecall, minecraftWorld, minecraftKeepAliveEvery, minecraftSessionMax, minecraftNow = origRecall, origWorld, origKA, origMax, origNow
	})
	remote := staticAddr{"95.165.3.78:40538"}
	_, _ = runMinecraftFrom(t, remote, func(c net.Conn) {
		_, _ = c.Write(append(mcHandshake(minecraft.PlayProtocol, minecraft.StateStatus), 0x01, 0x00))
		_, err := readMCPacket(c)
		require.NoError(t, err)
	})
	now = now.Add(2 * time.Hour)
	return remote
}

func mcString(s string) []byte {
	return append(minecraft.AppendVarInt(nil, int32(len(s))), s...)
}

// mcExpect reads one packet and checks it.
func mcExpect(t *testing.T, c net.Conn, want []byte) {
	t.Helper()
	got, err := readMCPacket(c)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// mcLoginToPlay drives a client from Handshake to Play on the open persona.
func mcLoginToPlay(t *testing.T, c net.Conn, w minecraft.World) {
	t.Helper()
	_, _ = c.Write(append(mcHandshake(minecraft.PlayProtocol, minecraft.StateLogin), mcDragonLogin...))
	mcExpect(t, c, minecraft.BuildLoginSuccess("DragonDima40"))
	_, _ = c.Write(minecraft.BuildPacket(minecraft.IDLoginAck, nil))
	mcExpect(t, c, minecraft.BuildConfigBrand())
	mcExpect(t, c, minecraft.BuildFeatureFlags())
	mcExpect(t, c, minecraft.BuildKnownPacks())
	_, _ = c.Write(minecraft.BuildPacket(minecraft.IDConfigCustomPayload, append(mcString("minecraft:brand"), mcString("vanilla")...)))
	_, _ = c.Write(minecraft.BuildPacket(minecraft.IDConfigClientInfo, append(mcString("en_us"), 0x0a, 0, 1, 0x7f, 1, 0, 1, 0)))
	_, _ = c.Write(minecraft.BuildPacket(minecraft.IDConfigKnownPacks, append([]byte{1}, append(append(mcString("minecraft"), mcString("core")...), mcString("1.21.8")...)...)))
	for range minecraft.RegistryCount() {
		_, err := readMCPacket(c)
		require.NoError(t, err)
	}
	mcExpect(t, c, minecraft.BuildFinishConfiguration())
	_, _ = c.Write(minecraft.BuildPacket(minecraft.IDConfigFinishAck, nil))
	mcExpect(t, c, minecraft.BuildPlayLogin(w))
	mcExpect(t, c, minecraft.BuildPlayerPosition(1, w))
	mcExpect(t, c, minecraft.BuildSpawnPosition(w))
	mcExpect(t, c, minecraft.BuildWaitForChunks())
	mcExpect(t, c, minecraft.BuildSystemChat("gold", mcPromptRegister))
}

func TestMinecraftOpenSession(t *testing.T) {
	remote := openMinecraftSource(t)
	w := minecraftWorld
	tickEnd := minecraft.BuildPacket(0x0C, nil)
	move := minecraft.BuildPacket(0x1D, make([]byte, 25))
	chat := minecraft.BuildPacket(minecraft.IDPlayChat, append(mcString("hi"), make([]byte, 21)...))
	register := minecraft.BuildPacket(minecraft.IDPlayChatCommand, mcString("register hunter2 hunter2"))
	op := minecraft.BuildPacket(minecraft.IDPlayChatCommand, mcString("op DragonDima40"))

	p, logger := runMinecraftFrom(t, remote, func(c net.Conn) {
		mcLoginToPlay(t, c, w)
		_, _ = c.Write(minecraft.BuildPacket(0x00, []byte{1})) // accept_teleportation
		_, _ = c.Write(chat)
		mcExpect(t, c, minecraft.BuildSystemChat("red", mcPromptLogin))
		_, _ = c.Write(register)
		mcExpect(t, c, minecraft.BuildSystemChat("green", mcRegistered))
		for range 50 {
			_, _ = c.Write(tickEnd)
			_, _ = c.Write(move)
		}
		_, _ = c.Write(op) // authed: no reply
	})

	frames := p.decoded.([]parsedMinecraft)
	type row struct{ dir, state, kind string }
	var got []row
	for _, f := range frames {
		got = append(got, row{f.Direction, f.State, minecraftFrameKind(f)})
	}
	require.Equal(t, []row{
		{"read", "", "handshake"},
		{"read", "", "login_start"},
		{"write", "login", "login_success"},
		{"read", "login", "login_acknowledged"},
		{"write", "configuration", "brand"},
		{"write", "configuration", "feature_flags"},
		{"write", "configuration", "known_packs"},
		{"read", "configuration", "custom_payload"},
		{"read", "configuration", "client_information"},
		{"read", "configuration", "select_known_packs"},
		{"write", "configuration", "registry_data"},
		{"write", "configuration", "finish_configuration"},
		{"read", "configuration", "finish_configuration"},
		{"write", "play", "login"},
		{"write", "play", "player_position"},
		{"write", "play", "spawn_position"},
		{"write", "play", "wait_for_chunks"},
		{"write", "play", "auth_prompt"},
		{"read", "play", "accept_teleportation"},
		{"read", "play", "chat"},
		{"write", "play", "auth_prompt"},
		{"read", "play", "chat_command"},
		{"write", "play", "auth_ok"},
		{"read", "play", "client_tick_end"},
		{"read", "play", "move_player_pos"},
		{"read", "play", "chat_command"},
	}, got)

	require.Equal(t, "3ebdb2dc-482f-37e1-9319-4763c25907bc", frames[1].UUID)
	require.Equal(t, parsedMinecraft{Direction: "write", Status: "login_success", State: "login", Variant: "smp", Visit: 2, Payload: minecraft.BuildLoginSuccess("DragonDima40")}, frames[2])
	require.Equal(t, "minecraft:brand", frames[7].Channel)
	require.Equal(t, "vanilla", frames[7].Brand)
	require.Equal(t, "en_us", frames[8].Locale)
	require.Equal(t, []string{"minecraft:core@1.21.8"}, frames[9].Packs)
	require.Equal(t, parsedMinecraft{Direction: "write", Status: "registry_data", State: "configuration", Count: minecraft.RegistryCount()}, frames[10])
	require.Equal(t, "hi", frames[19].Message)
	require.Equal(t, parsedMinecraft{Direction: "read", State: "play", Command: "chat_command", Message: "register hunter2 hunter2", Password: "hunter2", Payload: register}, frames[21])
	require.Equal(t, 50, frames[23].Count)
	require.Equal(t, tickEnd, frames[23].Payload)
	require.Equal(t, 50, frames[24].Count)
	require.Equal(t, "op DragonDima40", frames[25].Message)
	require.Empty(t, frames[25].Password)
	require.Empty(t, logger.errs)
}

func TestMinecraftOpenSessionKeepAlive(t *testing.T) {
	remote := openMinecraftSource(t)
	minecraftKeepAliveEvery = 10 * time.Millisecond
	ka := minecraft.BuildKeepAlive(true, minecraftNow().UnixMilli())
	p, _ := runMinecraftFrom(t, remote, func(c net.Conn) {
		_, _ = c.Write(append(mcHandshake(minecraft.PlayProtocol, minecraft.StateLogin), mcDragonLogin...))
		mcExpect(t, c, minecraft.BuildLoginSuccess("DragonDima40"))
		_, _ = c.Write(minecraft.BuildPacket(minecraft.IDLoginAck, nil))
		mcExpect(t, c, minecraft.BuildConfigBrand())
		mcExpect(t, c, minecraft.BuildFeatureFlags())
		mcExpect(t, c, minecraft.BuildKnownPacks())
		for range 3 {
			mcExpect(t, c, ka)
		}
	})
	frames := p.decoded.([]parsedMinecraft)
	last := frames[len(frames)-1]
	require.Equal(t, "keep_alive", last.Status)
	require.Equal(t, "configuration", last.State)
	require.GreaterOrEqual(t, last.Count, 3)
	require.Equal(t, ka, last.Payload)
}

func TestMinecraftOpenSessionLimits(t *testing.T) {
	remote := openMinecraftSource(t)
	minecraftSessionMax = 50 * time.Millisecond
	start := time.Now()
	p, _ := runMinecraftFrom(t, remote, func(c net.Conn) {
		_, _ = c.Write(append(mcHandshake(minecraft.PlayProtocol, minecraft.StateLogin), mcDragonLogin...))
		mcExpect(t, c, minecraft.BuildLoginSuccess("DragonDima40"))
		// The client idles; the server ends the session and closes.
		_, err := readMCPacket(c)
		require.Error(t, err)
	})
	require.Less(t, time.Since(start), time.Second)
	require.Len(t, p.decoded.([]parsedMinecraft), 3)

	// Frame cap: a flood of distinct, non-noisy packets.
	minecraftSessionMax = time.Hour
	loaded := minecraft.BuildPacket(0x2B, nil)
	p, _ = runMinecraftFrom(t, remote, func(c net.Conn) {
		mcLoginToPlay(t, c, minecraftWorld)
		for range maxMinecraftFrames {
			_, _ = c.Write(loaded)
		}
	})
	frames := p.decoded.([]parsedMinecraft)
	require.Len(t, frames, maxMinecraftFrames)
	require.True(t, frames[len(frames)-1].Truncated)
	require.Equal(t, "player_loaded", frames[len(frames)-1].Command)
}
