package smb

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSessionSetupIdentityFromOchi(t *testing.T) {
	raw, err := hex.DecodeString(
		"00000088ff534d4273000000001807c0" +
			"0000000000000000000000000000fffe" +
			"000040000dff00880004110a00000000" +
			"0000000100000000000000d40000004b" +
			"000000000000570069006e0064006f00" +
			"77007300200032003000300030002000" +
			"32003100390035000000570069006e00" +
			"64006f00770073002000320030003000" +
			"3000200035002e0030000000")
	require.NoError(t, err)
	buf, err := ValidateData(raw)
	require.NoError(t, err)
	header := SMBHeader{}
	require.NoError(t, ParseHeader(buf, &header))
	id := SessionSetupIdentity(header, buf.Bytes())
	require.Empty(t, id.Account)
	require.Equal(t, "Windows 2000 2195", id.NativeOS)
	require.Equal(t, "Windows 2000 5.0", id.NativeLanMan)
}

func TestSMBHeaderMarshalJSON(t *testing.T) {
	h := SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  0x32,
		Flags:    0x98,
		Flags2:   [2]byte{0x07, 0xc0},
	}
	binary.LittleEndian.PutUint32(h.Status[:], statusNotImplemented)
	binary.LittleEndian.PutUint16(h.TID[:], 1)
	binary.LittleEndian.PutUint16(h.UID[:], 1)
	binary.LittleEndian.PutUint16(h.MID[:], 0x41)
	binary.LittleEndian.PutUint16(h.PIDLow[:], 0xfeff)
	b, err := json.Marshal(h)
	require.NoError(t, err)
	var view map[string]any
	require.NoError(t, json.Unmarshal(b, &view))
	require.Equal(t, "STATUS_NOT_IMPLEMENTED", view["status_name"])
	require.Equal(t, "0xc007", view["flags2"])
	require.EqualValues(t, 1, view["tid"])
	require.NotContains(t, string(b), "Flags2")
}

func TestTrans2SetupName(t *testing.T) {
	require.Equal(t, "TRANS2_SESSION_SETUP", Trans2SetupName(Trans2SessionSetup))
	require.Equal(t, "TRANS2_FIND_FIRST2", Trans2SetupName(Trans2FindFirst2))
}

// basicSessionSetupBody builds a WordCount 13 Session Setup AndX body with
// Unicode strings (pad byte inserted for alignment after the passwords).
func basicSessionSetupBody(oem, uni []byte, strs ...string) []byte {
	b := []byte{0x0d, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x01, 0x00, 0, 0, 0, 0}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(oem)))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(uni)))
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)
	var data []byte
	data = append(data, oem...)
	data = append(data, uni...)
	if (32+27+len(data))%2 != 0 {
		data = append(data, 0)
	}
	for _, s := range strs {
		for _, r := range s {
			data = binary.LittleEndian.AppendUint16(data, uint16(r))
		}
		data = append(data, 0, 0)
	}
	b = binary.LittleEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func utf16le(s string) []byte {
	var out []byte
	for _, r := range s {
		out = binary.LittleEndian.AppendUint16(out, uint16(r))
	}
	return out
}

func TestSessionSetupIdentityPasswords(t *testing.T) {
	header := SMBHeader{Flags2: [2]byte{0x01, 0x80}} // Unicode
	lm := make([]byte, 24)
	for i := range lm {
		lm[i] = byte(i)
	}
	ntlmv2 := append(make([]byte, 16), 0x01, 0x01, 0x00, 0x00, 0, 0, 0, 0, 0xaa, 0xbb)

	for _, tc := range []struct {
		name     string
		oem, uni []byte
		want     SessionSetupFields
	}{
		{
			name: "unicode plaintext",
			uni:  utf16le("Winter2024!"),
			want: SessionSetupFields{Account: "administrator", Password: "Winter2024!", NativeOS: "Unix", NativeLanMan: "Samba"},
		},
		{
			name: "oem plaintext",
			oem:  []byte("hunter2\x00"),
			want: SessionSetupFields{Account: "administrator", Password: "hunter2", NativeOS: "Unix", NativeLanMan: "Samba"},
		},
		{
			name: "lm and ntlm responses",
			oem:  lm,
			uni:  lm,
			want: SessionSetupFields{Account: "administrator", LMResponse: hex.EncodeToString(lm), NTLMResponse: hex.EncodeToString(lm), NativeOS: "Unix", NativeLanMan: "Samba"},
		},
		{
			name: "ntlmv2 response only",
			uni:  ntlmv2,
			want: SessionSetupFields{Account: "administrator", NTLMResponse: hex.EncodeToString(ntlmv2), NativeOS: "Unix", NativeLanMan: "Samba"},
		},
		{
			name: "null session",
			want: SessionSetupFields{Account: "administrator", NativeOS: "Unix", NativeLanMan: "Samba"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := basicSessionSetupBody(tc.oem, tc.uni, "administrator", "WORKGROUP", "Unix", "Samba")
			require.Equal(t, tc.want, SessionSetupIdentity(header, body))
		})
	}
}
