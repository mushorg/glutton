package smb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLooksLikeSMB(t *testing.T) {
	// Censys SMB1 Negotiate captured on tcp/25026
	smb1 := []byte{0x00, 0x00, 0x00, 0x2f, 0xff, 'S', 'M', 'B', 0x72, 0, 0, 0, 0, 0x18, 0x43, 0xc8,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xfe,
		0, 0, 0, 0, 0, 0x0c, 0, 0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0}
	smb2 := append([]byte{0x00, 0x00, 0x00, 0x40, 0xfe, 'S', 'M', 'B'}, make([]byte, 60)...)
	nbss := append([]byte{0x81, 0x00, 0x00, 0x44, 0x20}, make([]byte, 8)...)

	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"smb1 negotiate", smb1, true},
		{"smb2 negotiate", smb2, true},
		{"nbss session request", nbss, true},
		{"short", smb1[:7], false},
		{"empty", nil, false},
		{"smb1 length too small", []byte{0x00, 0x00, 0x00, 0x04, 0xff, 'S', 'M', 'B', 0, 0, 0, 0}, false},
		{"wrong magic", []byte{0x00, 0x00, 0x00, 0x2f, 0xff, 'S', 'M', 'X', 0x72}, false},
		{"magic not at body start", []byte{0x00, 0x00, 0x00, 0x2f, 0x00, 0xff, 'S', 'M', 'B'}, false},
		{"reserved flag bits", []byte{0x00, 0x80, 0x00, 0x2f, 0xff, 'S', 'M', 'B', 0x72}, false},
		{"garbage", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, false},
		{"http", []byte("GET / HTTP/1.1\r\n"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, LooksLikeSMB(tt.in))
		})
	}
}

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
