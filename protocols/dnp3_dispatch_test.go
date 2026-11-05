package protocols

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/mushorg/glutton/protocols/tcp/dnp3"
	"github.com/stretchr/testify/require"
)

// The first three Request Link Status frames of a Censys DNP3 address sweep
// sent to tcp/16464 (dest 0, 1, 2; src 0).
var dnp3SweepCaptured = [][]byte{
	{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x36, 0x4c},
	{0x05, 0x64, 0x05, 0xc9, 0x01, 0x00, 0x00, 0x00, 0xde, 0x8e},
	{0x05, 0x64, 0x05, 0xc9, 0x02, 0x00, 0x00, 0x00, 0x9f, 0x84},
}

// dnp3SweepFrame builds the sweep's Request Link Status frame for dest.
func dnp3SweepFrame(dest uint16) []byte {
	b := []byte{0x05, 0x64, 0x05, 0xc9, 0, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(b[4:6], dest)
	binary.LittleEndian.PutUint16(b[8:10], dnp3.CRC(b[:8]))
	return b
}

func TestDNP3SweepFrameMatchesCapture(t *testing.T) {
	for i, want := range dnp3SweepCaptured {
		require.Equal(t, want, dnp3SweepFrame(uint16(i)))
	}
}

func TestCatchAllRoutesOffPortDNP3(t *testing.T) {
	ev := dispatchCatchAll(t, 16464, func(c net.Conn) {
		var sweep []byte
		for dest := uint16(0); dest <= 16; dest++ {
			sweep = append(sweep, dnp3SweepFrame(dest)...)
		}
		_, err := c.Write(sweep)
		require.NoError(t, err)
		// the default outstation address 10 answers with LINK_STATUS
		reply := make([]byte, dnp3.HeaderSize)
		_, err = io.ReadFull(c, reply)
		require.NoError(t, err)
		require.Equal(t, dnp3.Secondary(dnp3.FuncLinkStatus, 0, 10), reply)
	})
	require.Equal(t, "dnp3", ev.protocol)
	require.Equal(t, "read", ev.frames[0]["direction"])
	require.Equal(t, "REQUEST_LINK_STATUS", ev.frames[0]["command"])
	var statuses []any
	for _, f := range ev.frames {
		if f["direction"] == "write" {
			statuses = append(statuses, f["status"])
		}
	}
	require.Equal(t, []any{"LINK_STATUS"}, statuses)
}

func TestCatchAllDNP3BadCRCStaysTCP(t *testing.T) {
	ev := dispatchCatchAll(t, 16464, func(c net.Conn) {
		frame := dnp3SweepFrame(0)
		frame[9] ^= 0xff
		_, err := c.Write(frame)
		require.NoError(t, err)
		_, err = c.Read(make([]byte, 4096))
		require.NoError(t, err)
	})
	require.Equal(t, "tcp", ev.protocol)
}
