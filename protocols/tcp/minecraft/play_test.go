package minecraft

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTables(t *testing.T) {
	require.Len(t, configServerbound, 9)
	require.Len(t, playServerbound, 66)
	require.Equal(t, "select_known_packs", PacketName(true, IDConfigKnownPacks))
	require.Equal(t, "finish_configuration", PacketName(true, IDConfigFinishAck))
	require.Equal(t, "chat_command", PacketName(false, IDPlayChatCommand))
	require.Equal(t, "chat", PacketName(false, IDPlayChat))
	require.Equal(t, "custom_payload", PacketName(false, IDPlayCustomPayload))
	require.Equal(t, "player_loaded", PacketName(false, 0x2B))
	require.Empty(t, PacketName(false, 66))
	require.Empty(t, PacketName(true, -1))

	require.Len(t, syncedRegistries, 21)
	require.Equal(t, 21, RegistryCount())
	for _, r := range syncedRegistries {
		require.NotEmpty(t, r.Entries, r.ID)
		// Vanilla registers entries in sorted order; that order is the
		// numeric ID the client assigns.
		require.True(t, slices.IsSorted(r.Entries), r.ID)
		require.Len(t, slices.Compact(slices.Clone(r.Entries)), len(r.Entries), r.ID)
		if r.ID == "minecraft:dimension_type" {
			// BuildPlayLogin sends dimension type 0.
			require.Equal(t, "minecraft:overworld", r.Entries[0])
		}
	}
}

func TestOpenPersona(t *testing.T) {
	var open []string
	for _, p := range Personas {
		if p.Open {
			open = append(open, p.Name)
			require.EqualValues(t, PlayProtocol, p.Protocol, "only protocol 772 is implemented")
		}
	}
	require.Equal(t, []string{"smp"}, open)
	require.False(t, Personas[0].Open, "the first-visit persona keeps rejecting logins")
}

func TestBuildLoginSuccess(t *testing.T) {
	want := []byte{0x18, 0x02}
	// OfflineUUID("Notch") = b50ad385-829d-3141-a216-7e7d7539ba7f
	want = append(want, 0xb5, 0x0a, 0xd3, 0x85, 0x82, 0x9d, 0x31, 0x41, 0xa2, 0x16, 0x7e, 0x7d, 0x75, 0x39, 0xba, 0x7f)
	want = append(want, 0x05, 'N', 'o', 't', 'c', 'h', 0x00)
	require.Equal(t, want, BuildLoginSuccess("Notch"))
}

func TestBuildConfiguration(t *testing.T) {
	brand := append([]byte{0x18, 0x01, 0x0f}, "minecraft:brand"...)
	brand = append(brand, 0x06)
	brand = append(brand, "fabric"...)
	require.Equal(t, brand, BuildConfigBrand())

	flags := append([]byte{0x14, 0x0c, 0x01, 0x11}, "minecraft:vanilla"...)
	require.Equal(t, flags, BuildFeatureFlags())

	packs := []byte{0x18, 0x0e, 0x01, 0x09}
	packs = append(packs, "minecraft"...)
	packs = append(packs, 0x04)
	packs = append(packs, "core"...)
	packs = append(packs, 0x06)
	packs = append(packs, "1.21.8"...)
	require.Equal(t, packs, BuildKnownPacks())

	require.Equal(t, []byte{0x01, 0x03}, BuildFinishConfiguration())
	require.Equal(t, []byte{0x09, 0x04, 0, 0, 0x01, 0x9a, 0x63, 0x5b, 0x28, 0x00}, BuildKeepAlive(true, 0x19a635b2800))
	require.Equal(t, []byte{0x09, 0x26, 0, 0, 0, 0, 0, 0, 0, 0x2a}, BuildKeepAlive(false, 42))
}

func TestBuildRegistryData(t *testing.T) {
	data := BuildRegistryData()
	br := bytes.NewReader(data)
	var ids []string
	for br.Len() > 0 {
		pkt, err := ReadPacket(br)
		require.NoError(t, err)
		require.EqualValues(t, 0x07, pkt.ID)
		body := bytes.NewReader(pkt.Body)
		id, err := readString(body)
		require.NoError(t, err)
		n, _, err := ReadVarInt(body)
		require.NoError(t, err)
		for i := int32(0); i < n; i++ {
			_, err := readString(body)
			require.NoError(t, err)
			has, err := body.ReadByte()
			require.NoError(t, err)
			require.Zero(t, has, "entry data comes from the known pack")
		}
		require.Zero(t, body.Len())
		ids = append(ids, id)
	}
	require.Len(t, ids, 21)
	require.Equal(t, "minecraft:worldgen/biome", ids[0])
	require.Equal(t, "minecraft:dialog", ids[20])
	require.Less(t, len(data), 16*1024)
}

func TestBuildPlay(t *testing.T) {
	w := World{EntityID: 7, HashedSeed: -2, MaxPlayers: 10, X: 18357644, Y: 831, Z: -20882616}

	// Position example from minecraft.wiki Data types.
	spawn := BuildSpawnPosition(w)
	require.Equal(t, []byte{0x0d, 0x5a, 0x46, 0x07, 0x63, 0x2c, 0x15, 0xb4, 0x83, 0x3f, 0, 0, 0, 0}, spawn)

	login := []byte{0x2b, 0, 0, 0, 7, 0x00, 0x03}
	for _, d := range []string{"minecraft:overworld", "minecraft:the_nether", "minecraft:the_end"} {
		login = append(login, byte(len(d)))
		login = append(login, d...)
	}
	login = append(login, 10, 10, 10, 0, 1, 0, 0, 19)
	login = append(login, "minecraft:overworld"...)
	login = append(login, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe) // hashed seed -2
	login = append(login, 0, 0xff, 0, 0, 0, 0, 63, 0)
	require.Equal(t, append([]byte{byte(len(login))}, login...), BuildPlayLogin(w))

	pos := BuildPlayerPosition(1, World{X: 2, Y: 70, Z: -3})
	require.Len(t, pos, 2+1+6*8+2*4+4)
	require.Equal(t, []byte{byte(len(pos) - 1), 0x41, 0x01}, pos[:3])
	require.Equal(t, uint64(0x4004000000000000), binary.BigEndian.Uint64(pos[3:]))  // x 2.5
	require.Equal(t, uint64(0x4051800000000000), binary.BigEndian.Uint64(pos[11:])) // y 70
	require.Equal(t, uint64(0xc004000000000000), binary.BigEndian.Uint64(pos[19:])) // z -2.5

	require.Equal(t, []byte{0x06, 0x22, 13, 0, 0, 0, 0}, BuildWaitForChunks())

	chat := []byte{0x72, 0x0a, 0x08, 0, 5}
	chat = append(chat, "color"...)
	chat = append(chat, 0, 4)
	chat = append(chat, "gold"...)
	chat = append(chat, 0x08, 0, 4)
	chat = append(chat, "text"...)
	chat = append(chat, 0, 2, 'h', 'i', 0x00, 0x00)
	require.Equal(t, append([]byte{byte(len(chat))}, chat...), BuildSystemChat("gold", "hi"))
}

func TestParseServerbound(t *testing.T) {
	cmd, err := ParseChat(append([]byte{0x18}, "register hunter2 hunter2"...))
	require.NoError(t, err)
	require.Equal(t, "register hunter2 hunter2", cmd)

	brand := append([]byte{0x0f}, "minecraft:brand"...)
	brand = append(brand, 0x07)
	brand = append(brand, "vanilla"...)
	pm, err := ParsePluginMessage(brand)
	require.NoError(t, err)
	require.Equal(t, PluginMessage{Channel: "minecraft:brand", Brand: "vanilla"}, pm)
	pm, err = ParsePluginMessage(append(append([]byte{0x0b}, "fabric:sync"...), 0x01, 0x02))
	require.NoError(t, err)
	require.Equal(t, PluginMessage{Channel: "fabric:sync"}, pm)

	packs, err := ParseKnownPacks(BuildKnownPacks()[2:])
	require.NoError(t, err)
	require.Equal(t, []string{"minecraft:core@1.21.8"}, packs)
	_, err = ParseKnownPacks([]byte{0x7f})
	require.Error(t, err)

	locale, err := ParseClientLocale(append([]byte{0x05}, "en_us"...))
	require.NoError(t, err)
	require.Equal(t, "en_us", locale)
}

func TestParseAuthCommand(t *testing.T) {
	for cmd, want := range map[string]AuthCommand{
		"register hunter2 hunter2": {Verb: "register", Password: "hunter2"},
		"reg pw pw":                {Verb: "register", Password: "pw"},
		"LOGIN secret":             {Verb: "login", Password: "secret"},
		"l 123456":                 {Verb: "login", Password: "123456"},
		"log  spaced ":             {Verb: "login", Password: "spaced"},
	} {
		got, ok := ParseAuthCommand(cmd)
		require.True(t, ok, cmd)
		require.Equal(t, want, got, cmd)
	}
	for _, cmd := range []string{"login", "help", "op bob", ""} {
		_, ok := ParseAuthCommand(cmd)
		require.False(t, ok, cmd)
	}
}
