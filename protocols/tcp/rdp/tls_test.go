package rdp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsTLSRecord(t *testing.T) {
	require.True(t, IsTLSRecord([]byte{0x16, 0x03, 0x01, 0x00, 0x01}))
	require.True(t, IsTLSRecord([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46}))
	require.False(t, IsTLSRecord([]byte{0x03, 0x00, 0x00, 0x13}))
	require.False(t, IsTLSRecord([]byte{0x16, 0x02}))
	require.False(t, IsTLSRecord(nil))
}
