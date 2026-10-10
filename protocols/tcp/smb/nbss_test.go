package smb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// encodeNetBIOSName first-level encodes name padded to 15 bytes plus suffix.
func encodeNetBIOSName(name string, suffix byte) []byte {
	raw := []byte(name)
	for len(raw) < 15 {
		raw = append(raw, ' ')
	}
	raw = append(raw[:15], suffix)
	out := []byte{0x20}
	for _, c := range raw {
		out = append(out, 'A'+c>>4, 'A'+c&0x0f)
	}
	return append(out, 0x00)
}

func TestParseSessionRequest(t *testing.T) {
	// smbclient's default called name: "*SMBSERVER" with the 0x20 server suffix.
	called := []byte("\x20CKFDENECFDEFFCFGEFFCCACACACACACA\x00")
	require.Equal(t, encodeNetBIOSName("*SMBSERVER", 0x20), called)

	body := append(append([]byte{}, called...), encodeNetBIOSName("WORKSTATION", 0x00)...)
	gotCalled, gotCalling, ok := ParseSessionRequest(body)
	require.True(t, ok)
	require.Equal(t, "*SMBSERVER", gotCalled)
	require.Equal(t, "WORKSTATION", gotCalling)
}

func TestParseSessionRequestScope(t *testing.T) {
	called := encodeNetBIOSName("FILESRV", 0x20)
	// Replace the empty scope with "CORP" so the parser has to skip a label.
	called = append(called[:len(called)-1], append([]byte{4}, "CORP\x00"...)...)
	body := append(called, encodeNetBIOSName("PC1", 0x00)...)
	gotCalled, gotCalling, ok := ParseSessionRequest(body)
	require.True(t, ok)
	require.Equal(t, "FILESRV", gotCalled)
	require.Equal(t, "PC1", gotCalling)
}

func TestParseSessionRequestMalformed(t *testing.T) {
	valid := encodeNetBIOSName("HOST", 0x20)
	for name, body := range map[string][]byte{
		"empty":         nil,
		"bad length":    append([]byte{0x10}, valid[1:]...),
		"bad character": append([]byte{0x20, 'Z'}, valid[2:]...),
		"no terminator": valid[:len(valid)-1],
		"no calling":    valid,
		"short":         valid[:10],
	} {
		_, _, ok := ParseSessionRequest(body)
		require.False(t, ok, name)
	}
}

func TestNBSSTypeName(t *testing.T) {
	require.Equal(t, "NBSS_SESSION_REQUEST", NBSSTypeName(NBSSSessionRequest))
	require.Equal(t, "NBSS_SESSION_KEEP_ALIVE", NBSSTypeName(NBSSKeepAlive))
	require.Equal(t, "NBSS_0x99", NBSSTypeName(0x99))
	require.Equal(t, []byte{0x82, 0, 0, 0}, MakePositiveSessionResponse())
}
