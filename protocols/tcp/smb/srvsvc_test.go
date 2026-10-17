package smb

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/require"
)

// netShareEnumStub builds a NetrShareEnum request stub for server (may be "")
// and level, the way impacket/smbclient send it.
func netShareEnumStub(server string, level uint32) []byte {
	var b []byte
	u32 := func(v uint32) { b = binary.LittleEndian.AppendUint32(b, v) }
	if server == "" {
		u32(0)
	} else {
		w := append(utf16.Encode([]rune(server)), 0)
		u32(0x20000)
		u32(uint32(len(w)))
		u32(0)
		u32(uint32(len(w)))
		for _, c := range w {
			b = binary.LittleEndian.AppendUint16(b, c)
		}
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	u32(level)
	u32(level)
	u32(0x20004)
	u32(0)
	u32(0)
	u32(0xffffffff)
	u32(0x20008)
	u32(0)
	return b
}

func TestParseNetShareEnumLevel(t *testing.T) {
	for _, server := range []string{"", `\\10.0.0.1`, `\\a`} {
		for _, level := range []uint32{0, 1, 2} {
			got, ok := ParseNetShareEnumLevel(netShareEnumStub(server, level))
			require.True(t, ok, server)
			require.Equal(t, level, got, server)
		}
	}
}

func TestParseNetShareEnumLevelMalformed(t *testing.T) {
	_, ok := ParseNetShareEnumLevel(nil)
	require.False(t, ok)
	_, ok = ParseNetShareEnumLevel([]byte{1, 0, 0, 0, 1, 0, 0, 0})
	require.False(t, ok)
	// Absurd actual count must not panic or overflow.
	_, ok = ParseNetShareEnumLevel([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0})
	require.False(t, ok)
}

func TestBuildNetShareEnumResponseLevel1(t *testing.T) {
	pdu, ok := BuildNetShareEnumResponse(9, 0, 1, Shares)
	require.True(t, ok)
	h, ok := ParseDCERPCHeader(pdu)
	require.True(t, ok)
	require.Equal(t, byte(dcerpcPTypeResponse), h.PType)
	require.Equal(t, uint32(9), h.CallID)
	require.Equal(t, uint16(len(pdu)), h.FragLen)
	require.Zero(t, len(pdu)%4)

	stub := pdu[dcerpcHeaderLen+8:]
	require.Equal(t, uint32(len(stub)), binary.LittleEndian.Uint32(pdu[dcerpcHeaderLen:]))
	require.Equal(t, uint32(1), binary.LittleEndian.Uint32(stub[0:4])) // level
	require.Equal(t, uint32(len(Shares)), binary.LittleEndian.Uint32(stub[12:16]))
	// Trailer: TotalEntries, null ResumeHandle, WERR_OK.
	tail := stub[len(stub)-12:]
	require.Equal(t, uint32(len(Shares)), binary.LittleEndian.Uint32(tail[0:4]))
	require.Zero(t, binary.LittleEndian.Uint32(tail[4:8]))
	require.Zero(t, binary.LittleEndian.Uint32(tail[8:12]))

	for _, s := range Shares {
		w := utf16.Encode([]rune(s.Name))
		var enc []byte
		for _, c := range w {
			enc = binary.LittleEndian.AppendUint16(enc, c)
		}
		require.Contains(t, string(stub), string(enc), s.Name)
	}
}

func TestBuildNetShareEnumResponseLevel0AndUnsupported(t *testing.T) {
	pdu, ok := BuildNetShareEnumResponse(1, 0, 0, Shares)
	require.True(t, ok)
	h, _ := ParseDCERPCHeader(pdu)
	require.Equal(t, uint16(len(pdu)), h.FragLen)

	_, ok = BuildNetShareEnumResponse(1, 0, 2, Shares)
	require.False(t, ok)
}
