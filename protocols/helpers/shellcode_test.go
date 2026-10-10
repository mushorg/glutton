package helpers

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectShellcodeIndicators(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"pe-image", []byte("MZ\x90\x00........This program cannot be run in DOS mode....PE\x00\x00"), "pe-dos-stub"},
		{"fstenv-getpc", append([]byte{0xd9, 0x74, 0x24, 0xf4, 0x5b}, bytes.Repeat([]byte{0x41}, 8)...), "fstenv-getpc"},
		{"msf-x86", []byte{0xfc, 0xe8, 0x82, 0x00, 0x00, 0x00, 0x60, 0x89, 0xe5}, "msf-x86-prologue"},
		{"msf-x64", []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8}, "msf-x64-prologue"},
		{"call-pop", []byte{0x90, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x90}, "call-pop-getpc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := DetectShellcode(tc.data)
			require.Contains(t, res.Indicators, tc.want)
			require.Positive(t, res.Score)
		})
	}
}

func TestDetectShellcodeNOPSled(t *testing.T) {
	require.False(t, hasNOPSled(bytes.Repeat([]byte{0x90}, 15), minNOPSled))
	require.True(t, hasNOPSled(bytes.Repeat([]byte{0x90}, 16), minNOPSled))
	require.True(t, hasNOPSled(append([]byte("hi"), bytes.Repeat([]byte{0x90}, 20)...), minNOPSled))
}

func TestCallPopGetPCRequiresPop(t *testing.T) {
	// E8 00000000 not followed by a pop register is not a GetPC stub.
	require.False(t, hasCallPopGetPC([]byte{0xe8, 0x00, 0x00, 0x00, 0x00, 0x41}))
	require.True(t, hasCallPopGetPC([]byte{0xe8, 0x00, 0x00, 0x00, 0x00, 0x58}))
}

func TestLooksLikeShellcodeBenign(t *testing.T) {
	require.False(t, LooksLikeShellcode([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")))
	require.False(t, LooksLikeShellcode(bytes.Repeat([]byte{0x00}, 4096)))
	require.True(t, LooksLikeShellcode([]byte("MZxxThis program cannot be run in DOS mode"+"PE\x00\x00")))
}
