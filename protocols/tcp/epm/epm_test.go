package epm

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

// ept_lookup stub (40 bytes) from the request Shodan sends after binding the
// endpoint mapper on tcp/135: inquiry_type 0, no object, no Ifid,
// vers_option 1, nil entry_handle, max_ents 500.
var lookupStub = mustHex("00000000" + "00000000" + "00000000" + "01000000" +
	"0000000000000000000000000000000000000000" + "f4010000")

// Synthetic ept_map stub asking for samr (12345778-1234-abcd-ef00-0123456789ac
// v1.0) over NDR, as impacket's hept_map builds it (two floors kept).
var mapStub = mustHex(
	"01000000" + "00000000000000000000000000000000" + // object ptr + nil uuid
		"02000000" + "34000000" + "34000000" + // tower ptr, max_count, tower_length (52)
		"0200" + // floor_count
		"1300" + "0d" + "785734123412cdabef000123456789ac" + "0100" + "0200" + "0000" +
		"1300" + "0d" + "045d888aeb1cc9119fe808002b104860" + "0200" + "0200" + "0000" +
		"0000000000000000000000000000000000000000" + // entry_handle
		"04000000") // max_towers

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseLookup(t *testing.T) {
	req, ok := ParseLookup(lookupStub)
	require.True(t, ok)
	require.Equal(t, Request{Max: 500}, req)

	_, ok = ParseLookup(lookupStub[:30])
	require.False(t, ok)
}

func TestParseLookupWithInterface(t *testing.T) {
	stub := mustHex("00000000" + "00000000" + "01000000" +
		"785734123412cdabef000123456789ac" + "0100" + "0000" + // Ifid samr v1.0
		"01000000" + "0000000000000000000000000000000000000000" + "01000000")
	req, ok := ParseLookup(stub)
	require.True(t, ok)
	require.Equal(t, Request{Max: 1, Interface: "12345778-1234-abcd-ef00-0123456789ac", InterfaceVersion: "1.0"}, req)
}

func TestParseMap(t *testing.T) {
	req, ok := ParseMap(mapStub)
	require.True(t, ok)
	require.Equal(t, Request{Max: 4, Interface: "12345778-1234-abcd-ef00-0123456789ac", InterfaceVersion: "1.0"}, req)

	// a tower length past the stub
	bad := append([]byte(nil), mapStub...)
	bad[28] = 0xff
	_, ok = ParseMap(bad)
	require.False(t, ok)
}

func TestBuildEmptyResult(t *testing.T) {
	want := mustHex("0000000000000000000000000000000000000000" + // nil entry_handle
		"00000000" + // num_ents
		"f4010000" + "00000000" + "00000000" + // max_count 500, offset, actual_count
		"d6a0c916") // EPT_S_NOT_REGISTERED
	require.Equal(t, want, BuildEmptyResult(500))
}

func TestOpName(t *testing.T) {
	require.Equal(t, "ept_lookup", OpName(OpLookup))
	require.Equal(t, "ept_map", OpName(OpMap))
	require.Empty(t, OpName(7))
}
