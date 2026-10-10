package rdp

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// MCS Connect-Initial from ochi.mushmush.org/events/b4baa7aa-2d18-4e6e-83db-847c038a993e.
var mcsConnectInitialFixture = mustHex("0300019c02f0807f658201900401010401010101ff30190201220201020201000201010201000201010202ffff020102301902010102010102010102010102010002010102020420020102301c0202ffff0202fc170202ffff0201010201000201010202ffff0201020482012f000500147c00018126000800100001c00044756361811801c0d400040008000005200301ca03aa09080000280a000045004d0050002d004c00410050002d003000300031003400000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca010000000000100007000100370036003400380037002d004f0045004d002d0030003000310031003900300033002d0030003000310030003700000000000000000000000000000000000000000004c00c00090000000000000002c00c00100000000000000003c02c0003000000726470647200000000008080636c6970726472000000a0c0726470736e640000000000c0")

func TestParseClientData(t *testing.T) {
	cd := ParseClientData(mcsConnectInitialFixture)
	require.NotNil(t, cd)
	require.Equal(t, ClientData{
		ClientName:        "EMP-LAP-0014",
		ClientBuild:       2600,
		DesktopWidth:      1280,
		DesktopHeight:     800,
		KeyboardLayout:    0x0809,
		HighColorDepth:    16,
		EncryptionMethods: 0x10,
		Channels:          []string{"rdpdr", "cliprdr", "rdpsnd"},
	}, *cd)
}

func TestParseClientDataMalformed(t *testing.T) {
	require.Nil(t, ParseClientData(nil))
	require.Nil(t, ParseClientData([]byte("Duca")))
	// Block length larger than the data must not panic or read past it.
	require.Nil(t, ParseClientData(append([]byte("Duca\x08"), 0x01, 0xc0, 0xff, 0x00, 0, 0, 0, 0)))
	// Truncated fixture keeps whatever complete blocks there are.
	cut := mcsConnectInitialFixture[:len(mcsConnectInitialFixture)-60]
	cd := ParseClientData(cut)
	require.NotNil(t, cd)
	require.Equal(t, "EMP-LAP-0014", cd.ClientName)
	require.Empty(t, cd.Channels)
}

func TestMCSConnectResponseChannels(t *testing.T) {
	_, resp := MCSConnectResponse(ProtocolSSL, 3)
	// SC_NET: type, length 16, I/O 1003, count 3, IDs 1004-1006, pad.
	require.Contains(t, string(resp), string(mustHex("030c1000eb030300ec03ed03ee030000")))
	require.Equal(t, len(resp), int(binary.BigEndian.Uint16(resp[2:4])))

	_, resp = MCSConnectResponse(ProtocolSSL, 2)
	require.Contains(t, string(resp), string(mustHex("030c0c00eb030200ec03ed03")))
}

func TestMCSDomainPDUs(t *testing.T) {
	erect := mustHex("0300000c02f0800401000100")
	attach := mustHex("0300000802f08028")
	join := mustHex("0300000c02f08038000603ef")
	require.Equal(t, CmdErectDomainRequest, FrameCommand(erect))
	require.Equal(t, CmdAttachUserRequest, FrameCommand(attach))
	require.Equal(t, CmdChannelJoinRequest, FrameCommand(join))
	require.Equal(t, CmdMCSConnectInitial, FrameCommand(mcsConnectInitialFixture))
	require.Equal(t, CmdX224Data, FrameCommand(mustHex("0300000802f080ff")))

	initiator, channel, ok := ChannelJoinRequest(join)
	require.True(t, ok)
	require.Equal(t, uint16(6), initiator)
	require.Equal(t, uint16(1007), channel)
	_, _, ok = ChannelJoinRequest(attach)
	require.False(t, ok)

	// MS-RDPBCGR 4.1.7 and 4.1.9.
	_, auc := AttachUserConfirm()
	require.Equal(t, mustHex("0300000b02f0802e000006"), auc)
	_, cjc := ChannelJoinConfirm(6, 1007)
	require.Equal(t, mustHex("0300000f02f0803e00000603ef03ef"), cjc)
	require.Equal(t, CmdChannelJoinConfirm, FrameCommand(cjc))
}

func TestServerDenySequence(t *testing.T) {
	// MS-RDPBCGR 4.1.12: License Error PDU, valid client.
	_, lic := LicenseValidClient()
	require.Equal(t, mustHex("0300002202f08068000103eb701480000000ff031000070000000200000004000000"), lic)

	_, ei := SetErrorInfo(ErrInfoServerDeniedConnection)
	require.Equal(t, mustHex("0300002402f08068000103eb7016"), ei[:14])
	share := ei[14:]
	require.Len(t, share, 22)
	require.Equal(t, uint16(22), binary.LittleEndian.Uint16(share[0:2]))
	require.Equal(t, uint16(0x17), binary.LittleEndian.Uint16(share[2:4]))
	require.Equal(t, byte(0x2f), share[14])
	require.Equal(t, uint32(7), binary.LittleEndian.Uint32(share[18:22]))

	_, dpu := DisconnectProviderUltimatum()
	require.Equal(t, mustHex("0300000902f0802180"), dpu)
	require.Equal(t, CmdDisconnectProviderUltimatum, FrameCommand(dpu))
}

func TestSplitTPKT(t *testing.T) {
	erect := mustHex("0300000c02f0800401000100")
	attach := mustHex("0300000802f08028")

	pdus, rest := SplitTPKT(append(append([]byte{}, erect...), attach...))
	require.Equal(t, [][]byte{erect, attach}, pdus)
	require.Empty(t, rest)

	pdus, rest = SplitTPKT(append(append([]byte{}, erect...), attach[:5]...))
	require.Equal(t, [][]byte{erect}, pdus)
	require.Equal(t, attach[:5], rest)

	pdus, rest = SplitTPKT([]byte{0x03, 0x00})
	require.Empty(t, pdus)
	require.Equal(t, []byte{0x03, 0x00}, rest)

	junk := []byte("GET / HTTP/1.1\r\n\r\n")
	pdus, rest = SplitTPKT(junk)
	require.Equal(t, [][]byte{junk}, pdus)
	require.Empty(t, rest)
}

// clientInfoPayload builds Send Data user data: a basic security header with
// SEC_INFO_PKT and a Unicode TS_INFO_PACKET with extended info.
func clientInfoPayload(domain, user, password string) []byte {
	enc := func(s string) []byte { return utf16LE(s) }
	fields := [][]byte{enc(domain), enc(user), enc(password), enc(""), enc("")}
	b := []byte{0x40, 0x00, 0x00, 0x00}
	hdr := make([]byte, 18)
	binary.LittleEndian.PutUint32(hdr[4:8], infoUnicode|infoAutologon)
	for i, f := range fields {
		binary.LittleEndian.PutUint16(hdr[8+2*i:], uint16(len(f)))
	}
	b = append(b, hdr...)
	for _, f := range fields {
		b = append(append(b, f...), 0, 0)
	}
	addr := append(enc("10.0.0.5"), 0, 0)
	dir := append(enc(`C:\Windows\System32\mstscax.dll`), 0, 0)
	b = binary.LittleEndian.AppendUint16(b, 2)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(addr)))
	b = append(b, addr...)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(dir)))
	return append(b, dir...)
}

func TestParseClientInfo(t *testing.T) {
	ci, ok := ParseClientInfo(clientInfoPayload("CORP", "administrator", "Winter2024!"))
	require.True(t, ok)
	require.Equal(t, ClientInfo{
		Domain:        "CORP",
		Username:      "administrator",
		PasswordLen:   11,
		ClientAddress: "10.0.0.5",
		ClientDir:     `C:\Windows\System32\mstscax.dll`,
		Autologon:     true,
	}, ci)
	js, err := json.Marshal(ci)
	require.NoError(t, err)
	require.NotContains(t, string(js), "Winter2024!")
}

func TestParseClientInfoANSI(t *testing.T) {
	b := []byte{0x40, 0x00, 0x00, 0x00}
	hdr := make([]byte, 18)
	binary.LittleEndian.PutUint16(hdr[10:12], 4) // cbUserName
	binary.LittleEndian.PutUint16(hdr[12:14], 3) // cbPassword
	b = append(b, hdr...)
	b = append(b, 0)                     // domain
	b = append(b, []byte("root\x00")...) // user
	b = append(b, []byte("abc\x00")...)  // password
	b = append(b, 0, 0)                  // shell, dir
	ci, ok := ParseClientInfo(b)
	require.True(t, ok)
	require.Equal(t, ClientInfo{Username: "root", PasswordLen: 3}, ci)
}

func TestParseClientInfoEdgeCases(t *testing.T) {
	_, ok := ParseClientInfo(nil)
	require.False(t, ok)
	_, ok = ParseClientInfo([]byte{0x01, 0x00, 0x00, 0x00, 0xaa})
	require.False(t, ok, "security exchange is not client info")

	ci, ok := ParseClientInfo([]byte{0x48, 0x00, 0x00, 0x00, 0xde, 0xad})
	require.True(t, ok)
	require.Equal(t, ClientInfo{Encrypted: true}, ci)

	// Truncated after the username: keep what was complete.
	full := clientInfoPayload("", "guest", "pw")
	ci, ok = ParseClientInfo(full[:4+18+2+12])
	require.True(t, ok)
	require.Equal(t, "guest", ci.Username)
	require.Zero(t, ci.PasswordLen)
}

func TestParseCredSSPNTLMVersion(t *testing.T) {
	msg := make([]byte, 64)
	copy(msg, ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:12], NTLMMsgAuthenticate)
	for _, tc := range []struct {
		ntLen uint16
		want  string
	}{{0, "anonymous"}, {24, "NTLMv1"}, {300, "NTLMv2"}, {10, ""}} {
		binary.LittleEndian.PutUint16(msg[20:22], tc.ntLen)
		require.Equal(t, tc.want, ParseCredSSP(WrapTSRequest(msg)).NTLMVersion)
	}
}
