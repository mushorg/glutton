package banners

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// shodanTacacsProbe is the Shodan TACACS+ probe from Ochi event
// e184dcd6-9af0-49d9-bd26-ef5fafefe3c4 (tcp/49): an AUTHEN START header,
// session_id 0x00009bf9, with an empty body.
func shodanTacacsProbe(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString("c00101000000" + "9bf900000000")
	require.NoError(t, err)
	return b
}

func withTacacsKey(t *testing.T, key string) {
	t.Helper()
	orig := tacacsKey
	tacacsKey = []byte(key)
	t.Cleanup(func() { tacacsKey = orig })
}

// decryptTacacsBody undoes the MD5 pad of a reply, as the client would with
// the shared key.
func decryptTacacsBody(reply, key []byte) []byte {
	body := append([]byte{}, reply[tacacsHeaderLen:]...)
	tacacsXOR(reply[:tacacsHeaderLen], body, key)
	return body
}

func TestTacacsAuthenStart(t *testing.T) {
	withTacacsKey(t, "example-key")
	probe := shodanTacacsProbe(t)
	require.True(t, isTacacsAuthenStart(probe))

	resp, ok := ForPayload(probe)
	require.True(t, ok)
	require.Equal(t, "tacacs-authen-error", resp.Name)
	require.True(t, resp.Close)

	// computed independently from RFC 8907 4.5 with key "example-key"
	want, err := hex.DecodeString("c001020000009bf900000030" +
		"1d8d8579bc20edb671673ebcb62b3fb1db6932dba14ee39f" +
		"64e389279859ba252853279c84d34d8e8174a229692fef5e")
	require.NoError(t, err)
	require.Equal(t, want, resp.Data)
	require.Equal(t, len(resp.Data)-tacacsHeaderLen, int(binary.BigEndian.Uint32(resp.Data[8:12])))

	body := decryptTacacsBody(resp.Data, tacacsKey)
	require.Equal(t, []byte{tacacsStatusError, 0x00, 0x00, byte(len(tacacsTooShort)), 0x00, 0x00}, body[:6])
	require.Equal(t, tacacsTooShort, string(body[6:]))
}

func TestTacacsAuthenStartWithBody(t *testing.T) {
	withTacacsKey(t, "example-key")
	// minor version 1, single-connect requested, 16-byte body encrypted
	// with a key the honeypot does not know
	probe := shodanTacacsProbe(t)
	probe[0], probe[3] = 0xc1, 0x04
	probe[11] = 16
	probe = append(probe, make([]byte, 16)...)
	require.True(t, isTacacsAuthenStart(probe))

	resp, ok := ForPayload(probe)
	require.True(t, ok)
	require.Equal(t, "tacacs-authen-error", resp.Name)
	require.Equal(t, []byte{0xc1, 0x01, 0x02, 0x00, 0x00, 0x00, 0x9b, 0xf9}, resp.Data[:8])
	require.Equal(t, 6+len(tacacsCheckKeys), int(binary.BigEndian.Uint32(resp.Data[8:12])))

	body := decryptTacacsBody(resp.Data, tacacsKey)
	require.Equal(t, byte(tacacsStatusError), body[0])
	require.Equal(t, tacacsCheckKeys, string(body[6:]))
}

func TestTacacsAuthenStartRejects(t *testing.T) {
	mutate := func(f func(b []byte) []byte) []byte {
		return f(shodanTacacsProbe(t))
	}
	for name, data := range map[string][]byte{
		"empty":         nil,
		"short header":  shodanTacacsProbe(t)[:11],
		"bad major":     mutate(func(b []byte) []byte { b[0] = 0xb0; return b }),
		"bad minor":     mutate(func(b []byte) []byte { b[0] = 0xc2; return b }),
		"authorization": mutate(func(b []byte) []byte { b[1] = 0x02; return b }),
		"continue":      mutate(func(b []byte) []byte { b[2] = 0x03; return b }),
		"body missing":  mutate(func(b []byte) []byte { b[11] = 0x08; return b }),
		"trailing data": mutate(func(b []byte) []byte { return append(b, 0x00) }),
		"huge length":   mutate(func(b []byte) []byte { b[8] = 0xff; return b }),
	} {
		require.False(t, isTacacsAuthenStart(data), name)
		if resp, ok := ForPayload(data); ok {
			require.NotEqual(t, "tacacs-authen-error", resp.Name, name)
		}
	}
}
