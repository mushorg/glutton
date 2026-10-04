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
