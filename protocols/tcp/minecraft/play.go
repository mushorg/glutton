package minecraft

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// Offline-mode login for protocol 772 (Java 1.21.7/1.21.8): Login Success,
// the Configuration state and enough of Play for a client to spawn and chat.
// Only a persona with Open set gets this far; every ID and layout here is the
// 772 one (minecraft.wiki Java Edition protocol/Packets oldid 3258009, checked
// against PrismarineJS minecraft-data pc/1.21.8).

// PlayProtocol is the only protocol the open login speaks.
const PlayProtocol = 772

// Serverbound IDs the handler acts on.
const (
	IDLoginAck            = 0x03 // login: Login Acknowledged
	IDConfigClientInfo    = 0x00 // configuration: Client Information
	IDConfigCustomPayload = 0x02 // configuration: Plugin Message
	IDConfigFinishAck     = 0x03 // configuration: Acknowledge Finish Configuration
	IDConfigKnownPacks    = 0x07 // configuration: Known Packs
	IDPlayChatCommand     = 0x06
	IDPlayChatCommandSig  = 0x07
	IDPlayChat            = 0x08
	IDPlayClientInfo      = 0x0D
	IDPlayCustomPayload   = 0x15
)

// Clientbound IDs.
const (
	idLoginSuccess        = 0x02
	idConfigCustomPayload = 0x01
	idConfigFinish        = 0x03
	idConfigKeepAlive     = 0x04
	idConfigRegistryData  = 0x07
	idConfigFeatureFlags  = 0x0C
	idConfigKnownPacks    = 0x0E
	idPlayGameEvent       = 0x22
	idPlayKeepAlive       = 0x26
	idPlayLogin           = 0x2B
	idPlayPlayerPosition  = 0x41
	idPlaySpawnPosition   = 0x5A
	idPlaySystemChat      = 0x72

	// gameEventWaitForChunks is Game Event 13, which vanilla requires
	// before the client leaves the loading screen.
	gameEventWaitForChunks = 13
)

// ServerBrand is what the open persona reports on minecraft:brand: a Fabric
// server, whose status response is byte-identical to vanilla's, running an
// auth mod that asks offline-mode players to /register.
const ServerBrand = "fabric"

// knownPack is the vanilla data pack the client must also have for Registry
// Data to omit entry data.
var knownPack = [3]string{"minecraft", "core", "1.21.8"}

// PacketName returns Mojang's name for a serverbound configuration or play
// packet, or "" for an ID the state does not define.
func PacketName(configuration bool, id int32) string {
	tbl := playServerbound
	if configuration {
		tbl = configServerbound
	}
	if id < 0 || int(id) >= len(tbl) {
		return ""
	}
	return tbl[id]
}

func appendString(dst []byte, s string) []byte {
	dst = AppendVarInt(dst, int32(len(s)))
	return append(dst, s...)
}

func appendBool(dst []byte, v bool) []byte {
	if v {
		return append(dst, 1)
	}
	return append(dst, 0)
}

func appendDouble(dst []byte, v float64) []byte {
	return binary.BigEndian.AppendUint64(dst, math.Float64bits(v))
}

func appendFloat(dst []byte, v float32) []byte {
	return binary.BigEndian.AppendUint32(dst, math.Float32bits(v))
}

// offlineUUIDBytes is Java's UUID.nameUUIDFromBytes("OfflinePlayer:"+name).
func offlineUUIDBytes(name string) [16]byte {
	b := md5.Sum([]byte("OfflinePlayer:" + name))
	b[6] = b[6]&0x0f | 0x30
	b[8] = b[8]&0x3f | 0x80
	return b
}

// BuildLoginSuccess builds Login Success (0x02) the way an offline-mode
// server does: the offline UUID of name (whatever UUID the client sent) and
// no profile properties. There is no Set Compression before it, as with
// network-compression-threshold=-1.
func BuildLoginSuccess(name string) []byte {
	id := offlineUUIDBytes(name)
	body := append([]byte(nil), id[:]...)
	body = appendString(body, name)
	body = AppendVarInt(body, 0) // properties
	return BuildPacket(idLoginSuccess, body)
}

// BuildConfigBrand builds the configuration Plugin Message on minecraft:brand.
func BuildConfigBrand() []byte {
	body := appendString(nil, "minecraft:brand")
	return BuildPacket(idConfigCustomPayload, appendString(body, ServerBrand))
}

// BuildFeatureFlags enables the vanilla feature set.
func BuildFeatureFlags() []byte {
	body := AppendVarInt(nil, 1)
	return BuildPacket(idConfigFeatureFlags, appendString(body, "minecraft:vanilla"))
}

// BuildKnownPacks offers minecraft:core 1.21.8, as a 1.21.8 server does.
func BuildKnownPacks() []byte {
	body := AppendVarInt(nil, 1)
	for _, s := range knownPack {
		body = appendString(body, s)
	}
	return BuildPacket(idConfigKnownPacks, body)
}

// BuildRegistryData returns one Registry Data packet per synchronized
// registry, concatenated, with every entry's data left to the client's copy
// of minecraft:core.
func BuildRegistryData() []byte {
	var out []byte
	for _, r := range syncedRegistries {
		body := appendString(nil, r.ID)
		body = AppendVarInt(body, int32(len(r.Entries)))
		for _, e := range r.Entries {
			body = appendString(body, e)
			body = appendBool(body, false)
		}
		out = append(out, BuildPacket(idConfigRegistryData, body)...)
	}
	return out
}

// RegistryCount is the number of Registry Data packets BuildRegistryData
// returns.
func RegistryCount() int { return len(syncedRegistries) }

// BuildFinishConfiguration ends the Configuration state.
func BuildFinishConfiguration() []byte { return BuildPacket(idConfigFinish, nil) }

// BuildKeepAlive builds a Keep Alive for the configuration or play state.
func BuildKeepAlive(configuration bool, id int64) []byte {
	pid := int32(idPlayKeepAlive)
	if configuration {
		pid = idConfigKeepAlive
	}
	return BuildPacket(pid, binary.BigEndian.AppendUint64(nil, uint64(id)))
}

// World is where the open persona spawns players.
type World struct {
	EntityID   int32
	HashedSeed int64
	MaxPlayers int32
	X, Y, Z    int32 // spawn block
}

// BuildPlayLogin builds Login (play) for a survival player in the overworld
// (dimension type 0 in the synced registry), secure chat not enforced.
func BuildPlayLogin(w World) []byte {
	body := binary.BigEndian.AppendUint32(nil, uint32(w.EntityID))
	body = appendBool(body, false) // hardcore
	body = AppendVarInt(body, 3)
	for _, d := range []string{"minecraft:overworld", "minecraft:the_nether", "minecraft:the_end"} {
		body = appendString(body, d)
	}
	body = AppendVarInt(body, w.MaxPlayers)
	body = AppendVarInt(body, 10)  // view distance
	body = AppendVarInt(body, 10)  // simulation distance
	body = appendBool(body, false) // reduced debug info
	body = appendBool(body, true)  // respawn screen
	body = appendBool(body, false) // limited crafting
	body = AppendVarInt(body, 0)   // dimension type: minecraft:overworld
	body = appendString(body, "minecraft:overworld")
	body = binary.BigEndian.AppendUint64(body, uint64(w.HashedSeed))
	body = append(body, 0, 0xff)   // survival, no previous game mode
	body = appendBool(body, false) // debug
	body = appendBool(body, false) // flat
	body = appendBool(body, false) // no death location
	body = AppendVarInt(body, 0)   // portal cooldown
	body = AppendVarInt(body, 63)  // sea level
	body = appendBool(body, false) // enforces secure chat
	return BuildPacket(idPlayLogin, body)
}

// BuildPlayerPosition builds Synchronize Player Position to the centre of the
// spawn block, absolute, at rest.
func BuildPlayerPosition(teleportID int32, w World) []byte {
	body := AppendVarInt(nil, teleportID)
	body = appendDouble(body, float64(w.X)+0.5)
	body = appendDouble(body, float64(w.Y))
	body = appendDouble(body, float64(w.Z)+0.5)
	body = appendDouble(body, 0)
	body = appendDouble(body, 0)
	body = appendDouble(body, 0)
	body = appendFloat(body, 0) // yaw
	body = appendFloat(body, 0) // pitch
	body = binary.BigEndian.AppendUint32(body, 0)
	return BuildPacket(idPlayPlayerPosition, body)
}

// BuildSpawnPosition builds Set Default Spawn Position.
func BuildSpawnPosition(w World) []byte {
	pos := (uint64(w.X)&0x3ffffff)<<38 | (uint64(w.Z)&0x3ffffff)<<12 | uint64(w.Y)&0xfff
	body := binary.BigEndian.AppendUint64(nil, pos)
	return BuildPacket(idPlaySpawnPosition, appendFloat(body, 0))
}

// BuildWaitForChunks builds Game Event 13.
func BuildWaitForChunks() []byte {
	return BuildPacket(idPlayGameEvent, appendFloat([]byte{gameEventWaitForChunks}, 0))
}

// BuildSystemChat builds a System Chat Message whose content is the network
// NBT compound {color, text}. Text must be ASCII (NBT strings are modified
// UTF-8, identical to UTF-8 only there).
func BuildSystemChat(color, text string) []byte {
	body := []byte{0x0a} // nameless root compound
	body = appendNBTString(body, "color", color)
	body = appendNBTString(body, "text", text)
	body = append(body, 0x00)      // TAG_End
	body = appendBool(body, false) // chat, not action bar
	return BuildPacket(idPlaySystemChat, body)
}

func appendNBTString(dst []byte, name, value string) []byte {
	dst = append(dst, 0x08)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(name)))
	dst = append(dst, name...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(value)))
	return append(dst, value...)
}

// ParseChat returns the command (without "/") of a Chat Command or Signed
// Chat Command, or the message of a Chat Message: the leading string of each.
func ParseChat(body []byte) (string, error) {
	return readString(bytes.NewReader(body))
}

// PluginMessage is a serverbound Plugin Message. Brand is set for
// minecraft:brand, whose data is a string.
type PluginMessage struct {
	Channel string
	Brand   string
}

// ParsePluginMessage decodes the channel and, on minecraft:brand, the brand.
func ParsePluginMessage(body []byte) (PluginMessage, error) {
	br := bytes.NewReader(body)
	ch, err := readString(br)
	if err != nil {
		return PluginMessage{}, err
	}
	pm := PluginMessage{Channel: ch}
	if ch == "minecraft:brand" {
		pm.Brand, _ = readString(br)
	}
	return pm, nil
}

// ParseClientLocale returns the locale that leads Client Information.
func ParseClientLocale(body []byte) (string, error) {
	return readString(bytes.NewReader(body))
}

// maxKnownPacks bounds the packs recorded from one Known Packs packet.
const maxKnownPacks = 16

// ParseKnownPacks returns the client's packs as namespace:id@version.
func ParseKnownPacks(body []byte) ([]string, error) {
	br := bytes.NewReader(body)
	n, _, err := ReadVarInt(br)
	if err != nil {
		return nil, err
	}
	if n < 0 || n > maxKnownPacks {
		return nil, fmt.Errorf("%w: %d known packs", ErrBadString, n)
	}
	packs := make([]string, 0, n)
	for i := int32(0); i < n; i++ {
		var f [3]string
		for j := range f {
			if f[j], err = readString(br); err != nil {
				return packs, err
			}
		}
		packs = append(packs, f[0]+":"+f[1]+"@"+f[2])
	}
	return packs, nil
}

// AuthCommand is a /register or /login an auth mod would act on.
type AuthCommand struct {
	Verb     string // "register" or "login"
	Password string
}

// ParseAuthCommand recognizes register/reg and login/l/log commands (without
// the leading "/") and returns their first argument as the password.
func ParseAuthCommand(command string) (AuthCommand, bool) {
	fields := strings.Fields(command)
	if len(fields) < 2 {
		return AuthCommand{}, false
	}
	switch strings.ToLower(fields[0]) {
	case "register", "reg":
		return AuthCommand{Verb: "register", Password: fields[1]}, true
	case "login", "l", "log":
		return AuthCommand{Verb: "login", Password: fields[1]}, true
	}
	return AuthCommand{}, false
}
