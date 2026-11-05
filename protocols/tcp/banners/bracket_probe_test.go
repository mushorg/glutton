package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// shodanBracketProbe is the 46-byte probe captured on tcp/55000 from a
// Shodan-tagged source (209.38.70.156).
var shodanBracketProbe = []byte("\x00\x00\x00[38]\x00d\x00[8]\x00UmVtb3Rl[8]\x00cmVtb3Rl[8]\x00UmVtb3Rl")

func TestBracketProbe(t *testing.T) {
	require.Len(t, shodanBracketProbe, 46)
	resp, ok := ForPayload(shodanBracketProbe)
	require.True(t, ok)
	require.Equal(t, Response{Name: "bracket-probe", Silent: true}, resp)

	for name, p := range map[string]string{
		"outer length off":  "\x00\x00\x00[37]\x00d\x00[8]\x00UmVtb3Rl[8]\x00cmVtb3Rl[8]\x00UmVtb3Rl",
		"field overruns":    "\x00\x00\x00[14]\x00d\x00[9]\x00UmVtb3Rl",
		"no fields":         "\x00\x00\x00[2]\x00d\x00",
		"empty tag":         "\x00\x00\x00[13]\x00\x00[8]\x00UmVtb3Rl",
		"missing nul lead":  "\x00\x00[13]\x00d\x00[8]\x00UmVtb3Rl",
		"non-numeric len":   "\x00\x00\x00[xx]\x00d\x00[8]\x00UmVtb3Rl",
		"trailing garbage":  "\x00\x00\x00[15]\x00d\x00[8]\x00UmVtb3Rlx",
		"four nul prefix":   "\x00\x00\x00\x00",
		"bracket no prefix": "[13]\x00d\x00[8]\x00UmVtb3Rl",
	} {
		require.False(t, bracketProbe([]byte(p)), name)
	}
}
