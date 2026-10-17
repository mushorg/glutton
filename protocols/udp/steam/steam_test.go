package steam

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured Censys discovery probe (Ochi event 2aa6e947-f427-4454-9776-3f34171ac06f).
const capturedDiscovery = "ffffffff214c5fa00a000000089acc97eea3cd021000020000000800"

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestParseDiscovery(t *testing.T) {
	m, err := Parse(decode(t, capturedDiscovery))
	require.NoError(t, err)
	require.Equal(t, Message{ClientID: 11451419190810, MsgType: MsgDiscovery, HasHeader: true}, m)
	require.Equal(t, "11451419190810", m.ClientIDString())
	require.Equal(t, "discovery", Name(m.MsgType))
}

func TestParseSequenceNum(t *testing.T) {
	// header {client_id: 1, msg_type: 0}, body {sequence_num: 7}
	m, err := Parse(decode(t, "ffffffff214c5fa004000000080110000200000008"+"07"))
	require.NoError(t, err)
	require.Equal(t, uint32(7), m.SequenceNum)
}

func TestParseNonDiscoveryIgnoresBody(t *testing.T) {
	// header {client_id: 1, msg_type: 1 (status)}, body {field 1: 9}
	m, err := Parse(decode(t, "ffffffff214c5fa004000000080110010200000008"+"09"))
	require.NoError(t, err)
	require.Equal(t, uint64(1), m.MsgType)
	require.Zero(t, m.SequenceNum)
	require.Equal(t, "status", Name(m.MsgType))
}

func TestParseErrors(t *testing.T) {
	full := decode(t, capturedDiscovery)
	cases := map[string][]byte{
		"no magic":         []byte("hello world, not steam"),
		"magic only":       full[:8],
		"short hdr len":    full[:10],
		"header overrun":   decode(t, "ffffffff214c5fa0ff000000089acc"),
		"header only":      full[:8+4+10],
		"body overrun":     decode(t, "ffffffff214c5fa00a000000089acc97eea3cd021000ff0000000800"),
		"bad header proto": decode(t, "ffffffff214c5fa00200000008800200000000"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(data)
			require.Error(t, err)
		})
	}
}

func TestParseKeepsPartialHeaderOnBodyError(t *testing.T) {
	m, err := Parse(decode(t, "ffffffff214c5fa00a000000089acc97eea3cd021000ff0000000800"))
	require.Error(t, err)
	require.True(t, m.HasHeader)
	require.Equal(t, uint64(11451419190810), m.ClientID)
}

func TestLooksLikeSteam(t *testing.T) {
	require.True(t, LooksLikeSteam(decode(t, capturedDiscovery)))
	require.True(t, LooksLikeSteam(Magic))
	require.False(t, LooksLikeSteam(Magic[:7]))
	require.False(t, LooksLikeSteam(decode(t, "ffffffff54536f7572636520456e67696e6520517565727900"))) // A2S_INFO
	require.False(t, LooksLikeSteam(nil))
}

func TestNameUnknown(t *testing.T) {
	require.Equal(t, "UNKNOWN", Name(99))
}
