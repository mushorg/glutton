package tcp

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/recall"
	"github.com/mushorg/glutton/protocols/tcp/minecraft"
)

const maxMinecraftPackets = 16

// minecraftLingerWait bounds the read of a Login Start already in flight when
// a login Handshake is rejected, so its username is still captured. Tests
// shorten it.
var minecraftLingerWait = 500 * time.Millisecond

type parsedMinecraft struct {
	Direction       string `json:"direction,omitempty"`
	Command         string `json:"command,omitempty"`
	Path            string `json:"path,omitempty"` // server address from the handshake
	Status          string `json:"status,omitempty"`
	ProtocolVersion *int32 `json:"protocol_version,omitempty"`
	Port            uint16 `json:"port,omitempty"`
	NextState       int32  `json:"next_state,omitempty"`
	Username        string `json:"username,omitempty"`
	UUID            string `json:"uuid,omitempty"` // player UUID from Login Start (1.19.3+)
	// Open-persona sessions past Login Success.
	State     string   `json:"state,omitempty"`    // "login", "configuration" or "play"
	Message   string   `json:"message,omitempty"`  // chat message, or chat command without "/"
	Password  string   `json:"password,omitempty"` // first argument of /register or /login
	Channel   string   `json:"channel,omitempty"`  // plugin message channel
	Brand     string   `json:"brand,omitempty"`    // client brand on minecraft:brand
	Locale    string   `json:"locale,omitempty"`   // Client Information locale
	Packs     []string `json:"packs,omitempty"`    // client Known Packs, namespace:id@version
	Count     int      `json:"count,omitempty"`    // repeats folded into this frame
	Variant   string   `json:"variant,omitempty"`  // persona, on status/disconnect writes
	Visit     int      `json:"visit,omitempty"`    // source's visit number, on the status_response write
	Payload   []byte   `json:"payload,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

type minecraftServer struct {
	events []parsedMinecraft
	conn   net.Conn
	r      io.Reader // conn behind a buffer, so a legacy ping can be sniffed

	// Recall: the persona is picked once per connection.
	srcIP   net.IP
	visit   int // 0 until begin
	persona minecraft.Persona
	store   *recall.Store
}

// minecraftRecall remembers each source's last visit; tests swap it for a
// store with a fake clock.
var minecraftRecall = recall.Shared

// begin picks the persona once per connection: a source returning after
// recall.visit_gap gets the next minecraft.Personas entry.
func (s *minecraftServer) begin(logger interfaces.Logger) {
	if s.visit > 0 {
		return
	}
	s.store = minecraftRecall
	v := s.store.Begin("minecraft", s.srcIP, len(minecraft.Personas))
	s.visit, s.persona = v.Number, minecraft.Personas[v.Variant]
	if v.Started && v.Number > 1 {
		logger.Info("returning Minecraft source",
			slog.String("protocol", "minecraft"),
			slog.String("src_ip", s.srcIP.String()),
			slog.Int("visit", v.Number),
			slog.String("variant", s.persona.Name),
			slog.String("previous_variant", v.Previous.Variant),
			slog.Any("previous_commands", v.Previous.Commands),
		)
	}
}

// note stores what the source did on this connection.
func (s *minecraftServer) note() {
	if s.visit == 0 {
		return
	}
	s.store.Note("minecraft", s.srcIP, func(sum *recall.Summary) {
		sum.Variant = s.persona.Name
		sum.Events++
		for _, e := range s.events {
			if e.Direction != "read" {
				continue
			}
			sum.AddCommand(e.Command)
			sum.AddPath(e.Path)
			sum.AddUsername(e.Username)
		}
	})
}

// tagLast stamps the last write frame with the visit's persona.
func (s *minecraftServer) tagLast() {
	ev := &s.events[len(s.events)-1]
	ev.Variant = s.persona.Name
	ev.Visit = s.visit
}

func (s *minecraftServer) write(data []byte, status string) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.events = append(s.events, parsedMinecraft{Direction: "write", Status: status, Payload: data})
	return nil
}

// disconnect sends a login Disconnect; the frame status is the reason key
// without its "multiplayer.disconnect." prefix (e.g. "not_whitelisted"). The
// frame carries the persona, whose version decides the version reasons.
func (s *minecraftServer) disconnect(reason string) error {
	if err := s.write(minecraft.BuildLoginDisconnect(s.persona, reason), strings.TrimPrefix(reason, "multiplayer.disconnect.")); err != nil {
		return err
	}
	s.tagLast()
	return nil
}

// readLingeringLogin records a Login Start the client sent before it saw the
// Disconnect. Nothing is answered.
func (s *minecraftServer) readLingeringLogin() {
	// Best effort: bytes already buffered are read even if the deadline
	// cannot be set (the peer has gone away).
	_ = s.conn.SetReadDeadline(time.Now().Add(minecraftLingerWait))
	pkt, err := minecraft.ReadPacket(s.r)
	if err != nil {
		if len(pkt.Raw) > 0 {
			s.events = append(s.events, parsedMinecraft{Direction: "read", Command: "malformed", Payload: pkt.Raw, Truncated: true})
		}
		return
	}
	s.events = append(s.events, loginStartFrame(pkt))
}

// maxLegacyPing caps the bytes recorded for a legacy ping: FE 01 plus the
// FA MC|PingHost message is about 30 bytes plus the host name.
const maxLegacyPing = 256

// sniffLegacyPing consumes and returns a pre-1.7 server list ping if one
// starts the connection, else nil with nothing consumed. It never waits for
// more than the two bytes that tell the ping apart; the plugin message is
// taken from what already arrived with them.
func (s *minecraftServer) sniffLegacyPing(br *bufio.Reader) []byte {
	if first, err := br.Peek(1); err != nil || first[0] != 0xfe {
		return nil
	}
	if _, err := br.Peek(minecraft.LegacyPingLen); err != nil {
		return nil
	}
	buffered, _ := br.Peek(min(br.Buffered(), maxLegacyPing))
	if !minecraft.LooksLikeLegacyPing(buffered) {
		return nil
	}
	raw := make([]byte, len(buffered))
	_, _ = io.ReadFull(br, raw)
	return raw
}

func loginStartFrame(pkt minecraft.Packet) parsedMinecraft {
	frame := parsedMinecraft{Direction: "read", Command: "unknown", Payload: pkt.Raw}
	if pkt.ID == minecraft.IDLoginStart {
		frame.Command = "login_start"
		if ls, err := minecraft.ParseLoginStart(pkt.Body); err == nil {
			frame.Username = ls.Name
			frame.UUID = ls.UUID
		}
	}
	return frame
}

// HandleMinecraft answers Minecraft Java server-list pings and records login attempts.
func HandleMinecraft(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	br := bufio.NewReader(conn)
	server := &minecraftServer{events: []parsedMinecraft{}, conn: conn, r: br, srcIP: remoteIP(conn), persona: minecraft.Personas[0]}
	defer func() {
		server.note()
		if err := h.ProduceTCP("minecraft", conn, md, helpers.FirstOrEmpty[parsedMinecraft](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close Minecraft connection", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
		}
	}()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		logger.Debug("Failed to set connection timeout", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
		return nil
	}
	if legacy := server.sniffLegacyPing(br); legacy != nil {
		server.events = append(server.events, parsedMinecraft{Direction: "read", Command: "legacy_ping", Payload: legacy})
		server.begin(logger)
		if err := server.write(minecraft.BuildLegacyKick(server.persona), "legacy_status_response"); err != nil {
			logger.Error("Failed to write message", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
			return err
		}
		server.tagLast()
		return nil
	}

	var (
		state      int32 // 0 handshake, then minecraft.StateStatus / StateLogin
		handshook  bool
		statusSent bool
	)

	for i := 0; i < maxMinecraftPackets; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
			return nil
		}
		pkt, err := minecraft.ReadPacket(br)
		if err != nil {
			if len(pkt.Raw) > 0 {
				// Partial or rejected frame: keep what the attacker sent.
				server.events = append(server.events, parsedMinecraft{
					Direction: "read",
					Command:   "malformed",
					Payload:   pkt.Raw,
					Truncated: true,
				})
			}
			logger.Debug("Failed to read data", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
			return nil
		}
		frame := parsedMinecraft{Direction: "read", Payload: pkt.Raw}

		switch {
		case !handshook:
			hs, err := minecraft.ParseHandshake(pkt.Body)
			if pkt.ID != minecraft.IDHandshake || err != nil {
				frame.Command = "unknown"
				server.events = append(server.events, frame)
				return nil
			}
			handshook = true
			state = hs.NextState
			frame.Command = "handshake"
			frame.Path = hs.Address
			frame.ProtocolVersion = &hs.ProtocolVersion
			frame.Port = hs.Port
			frame.NextState = hs.NextState
			server.events = append(server.events, frame)
			server.begin(logger)
			// Vanilla rejects transfers and version mismatches right after
			// the Handshake, before Login Start.
			var reason string
			switch state {
			case minecraft.StateStatus:
			case minecraft.StateLogin:
				reason = minecraft.VersionReason(server.persona, hs.ProtocolVersion)
			case minecraft.StateTransfer:
				reason = minecraft.ReasonTransfersDisabled
			default:
				return nil
			}
			if reason != "" {
				if err := server.disconnect(reason); err != nil {
					return err
				}
				server.readLingeringLogin()
				return nil
			}

		case state == minecraft.StateStatus && pkt.ID == minecraft.IDStatusReq:
			frame.Command = "status_request"
			server.events = append(server.events, frame)
			if statusSent {
				// Vanilla closes on a second Status Request.
				return nil
			}
			statusSent = true
			if err := server.write(minecraft.BuildStatusResponse(server.persona), "status_response"); err != nil {
				return err
			}
			server.tagLast()

		case state == minecraft.StateStatus && pkt.ID == minecraft.IDPing:
			frame.Command = "ping"
			server.events = append(server.events, frame)
			ping, err := minecraft.ParsePing(pkt.Body)
			if err != nil {
				return nil
			}
			return server.write(minecraft.BuildPong(ping), "pong")

		case state == minecraft.StateLogin && pkt.ID == minecraft.IDLoginStart:
			login := loginStartFrame(pkt)
			server.events = append(server.events, login)
			if !server.persona.Open || login.Username == "" {
				return server.disconnect(minecraft.ReasonNotWhitelisted)
			}
			return server.openSession(ctx, h, logger, login.Username)

		default:
			frame.Command = "unknown"
			server.events = append(server.events, frame)
			return nil
		}
	}
	return nil
}

// Open-persona session bounds and test seams.
var (
	// minecraftKeepAliveEvery paces Keep Alive; vanilla clients drop a
	// server silent for ~20 s and vanilla sends one every 15 s.
	minecraftKeepAliveEvery = 15 * time.Second
	// minecraftSessionMax ends a logged-in session however active it is.
	minecraftSessionMax = 2 * time.Minute
	minecraftNow        = time.Now
	// minecraftWorld is the open persona's world: seed and spawn are picked
	// once per process, so sensors differ and a returning bot sees the same
	// world.
	minecraftWorld = newMinecraftWorld()
)

const (
	// maxMinecraftSessionPackets bounds packets read after Login Success.
	maxMinecraftSessionPackets = 4096
	// maxMinecraftFrames bounds the frames one session records; the last
	// kept frame is marked truncated when more were dropped.
	maxMinecraftFrames = 256
)

func newMinecraftWorld() minecraft.World {
	return minecraft.World{
		EntityID:   int32(100 + rand.IntN(4000)),
		HashedSeed: rand.Int64(),
		MaxPlayers: 10,
		X:          int32(rand.IntN(512) - 256),
		Y:          int32(64 + rand.IntN(16)),
		Z:          int32(rand.IntN(512) - 256),
	}
}

// Auth mod chat lines (EasyAuth-style; a guess at a plausible wording).
const (
	mcPromptRegister = "Please register with /register <password> <password>"
	mcPromptLogin    = "You need to log in first: /login <password>"
	mcRegistered     = "Successfully registered! You are now logged in."
	mcLoggedIn       = "Successfully logged in."
)

// noisyMinecraft are packets a client sends every tick or every keep-alive.
// They fold into an earlier frame of the same kind (Count) as long as only
// noisy frames came after it.
var noisyMinecraft = map[string]bool{
	"accept_teleportation":    true,
	"chat_ack":                true,
	"chunk_batch_received":    true,
	"client_tick_end":         true,
	"keep_alive":              true,
	"move_player_pos":         true,
	"move_player_pos_rot":     true,
	"move_player_rot":         true,
	"move_player_status_only": true,
	"player_input":            true,
	"swing":                   true,
}

func minecraftFrameKind(f parsedMinecraft) string {
	if f.Direction == "write" {
		return f.Status
	}
	return f.Command
}

// record appends a session frame, folding noisy repeats and enforcing
// maxMinecraftFrames.
func (s *minecraftServer) record(f parsedMinecraft) {
	if kind := minecraftFrameKind(f); noisyMinecraft[kind] {
		for i := len(s.events) - 1; i >= 0; i-- {
			prev := &s.events[i]
			pk := minecraftFrameKind(*prev)
			if !noisyMinecraft[pk] {
				break
			}
			if pk == kind && prev.Direction == f.Direction && prev.State == f.State {
				prev.Count = max(prev.Count, 1) + 1
				return
			}
		}
	}
	if len(s.events) >= maxMinecraftFrames {
		s.events[len(s.events)-1].Truncated = true
		return
	}
	s.events = append(s.events, f)
}

// send writes one or more packets and records them as one write frame.
func (s *minecraftServer) send(data []byte, status, state string) error {
	if _, err := s.conn.Write(data); err != nil {
		return err
	}
	s.record(parsedMinecraft{Direction: "write", Status: status, State: state, Payload: data})
	return nil
}

type minecraftRead struct {
	pkt minecraft.Packet
	err error
}

// openSession runs an accepted offline-mode login: Login Success, then the
// Configuration state (brand, feature flags, known packs, registries), then
// Play (spawn and an auth mod's /register prompt), recording everything the
// client sends until it leaves or a bound is hit. A reader goroutine feeds
// packets so Keep Alive can go out on time; only this goroutine touches
// s.events.
func (s *minecraftServer) openSession(ctx context.Context, h interfaces.Honeypot, logger interfaces.Logger, name string) error {
	logger.Info("Minecraft login accepted",
		slog.String("handler", "minecraft"),
		slog.String("protocol", "minecraft"),
		slog.String("src_ip", s.srcIP.String()),
		slog.String("username", name),
	)
	state := "login"
	if err := s.send(minecraft.BuildLoginSuccess(name), "login_success", state); err != nil {
		return err
	}
	s.tagLast()

	reads := make(chan minecraftRead)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			pkt, err := minecraft.ReadPacket(s.r)
			select {
			case reads <- minecraftRead{pkt: pkt, err: err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	keepAlive := time.NewTicker(minecraftKeepAliveEvery)
	defer keepAlive.Stop()
	end := time.NewTimer(minecraftSessionMax)
	defer end.Stop()

	world := minecraftWorld
	authed := false
	for n := 0; n < maxMinecraftSessionPackets; {
		var r minecraftRead
		select {
		case <-ctx.Done():
			return nil
		case <-end.C:
			logger.Debug("Minecraft session limit reached", slog.String("protocol", "minecraft"))
			return nil
		case <-keepAlive.C:
			if state == "login" {
				continue
			}
			ka := minecraft.BuildKeepAlive(state == "configuration", minecraftNow().UnixMilli())
			if err := s.send(ka, "keep_alive", state); err != nil {
				return err
			}
			continue
		case r = <-reads:
			n++
		}
		if r.err != nil {
			if len(r.pkt.Raw) > 0 {
				s.record(parsedMinecraft{Direction: "read", State: state, Command: "malformed", Payload: r.pkt.Raw, Truncated: true})
			}
			logger.Debug("Failed to read data", slog.String("protocol", "minecraft"), producer.ErrAttr(r.err))
			return nil
		}
		if err := h.UpdateConnectionTimeout(ctx, s.conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "minecraft"), producer.ErrAttr(err))
			return nil
		}
		pkt := r.pkt
		frame := parsedMinecraft{Direction: "read", State: state, Payload: pkt.Raw}

		switch state {
		case "login":
			if pkt.ID != minecraft.IDLoginAck {
				frame.Command = "unknown"
				s.record(frame)
				return nil
			}
			frame.Command = "login_acknowledged"
			s.record(frame)
			state = "configuration"
			for _, w := range []struct {
				data   []byte
				status string
			}{
				{minecraft.BuildConfigBrand(), "brand"},
				{minecraft.BuildFeatureFlags(), "feature_flags"},
				{minecraft.BuildKnownPacks(), "known_packs"},
			} {
				if err := s.send(w.data, w.status, state); err != nil {
					return err
				}
			}

		case "configuration":
			frame.Command = minecraftPacketName(true, pkt.ID)
			switch pkt.ID {
			case minecraft.IDConfigClientInfo:
				frame.Locale, _ = minecraft.ParseClientLocale(pkt.Body)
			case minecraft.IDConfigCustomPayload:
				setPluginMessage(&frame, pkt.Body)
			case minecraft.IDConfigKnownPacks:
				frame.Packs, _ = minecraft.ParseKnownPacks(pkt.Body)
			}
			s.record(frame)
			switch pkt.ID {
			case minecraft.IDConfigKnownPacks:
				// The registries are the same bytes every session; the
				// frame keeps the packet count, not the ~8 KB payload.
				if _, err := s.conn.Write(minecraft.BuildRegistryData()); err != nil {
					return err
				}
				s.record(parsedMinecraft{Direction: "write", Status: "registry_data", State: state, Count: minecraft.RegistryCount()})
				if err := s.send(minecraft.BuildFinishConfiguration(), "finish_configuration", state); err != nil {
					return err
				}
			case minecraft.IDConfigFinishAck:
				state = "play"
				for _, w := range []struct {
					data   []byte
					status string
				}{
					{minecraft.BuildPlayLogin(world), "login"},
					{minecraft.BuildPlayerPosition(1, world), "player_position"},
					{minecraft.BuildSpawnPosition(world), "spawn_position"},
					{minecraft.BuildWaitForChunks(), "wait_for_chunks"},
					{minecraft.BuildSystemChat("gold", mcPromptRegister), "auth_prompt"},
				} {
					if err := s.send(w.data, w.status, state); err != nil {
						return err
					}
				}
			}

		case "play":
			frame.Command = minecraftPacketName(false, pkt.ID)
			var reply []byte
			var status string
			switch pkt.ID {
			case minecraft.IDPlayChatCommand, minecraft.IDPlayChatCommandSig:
				frame.Message, _ = minecraft.ParseChat(pkt.Body)
				if auth, ok := minecraft.ParseAuthCommand(frame.Message); ok {
					frame.Password = auth.Password
					if !authed {
						authed = true
						reply, status = minecraft.BuildSystemChat("green", mcLoggedIn), "auth_ok"
						if auth.Verb == "register" {
							reply = minecraft.BuildSystemChat("green", mcRegistered)
						}
					}
				} else if !authed {
					reply, status = minecraft.BuildSystemChat("red", mcPromptLogin), "auth_prompt"
				}
			case minecraft.IDPlayChat:
				frame.Message, _ = minecraft.ParseChat(pkt.Body)
				if !authed {
					reply, status = minecraft.BuildSystemChat("red", mcPromptLogin), "auth_prompt"
				}
			case minecraft.IDPlayClientInfo:
				frame.Locale, _ = minecraft.ParseClientLocale(pkt.Body)
			case minecraft.IDPlayCustomPayload:
				setPluginMessage(&frame, pkt.Body)
			}
			s.record(frame)
			if reply != nil {
				if err := s.send(reply, status, state); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func minecraftPacketName(configuration bool, id int32) string {
	if name := minecraft.PacketName(configuration, id); name != "" {
		return name
	}
	return "unknown"
}

func setPluginMessage(f *parsedMinecraft, body []byte) {
	if pm, err := minecraft.ParsePluginMessage(body); err == nil {
		f.Channel, f.Brand = pm.Channel, pm.Brand
	}
}
