package protocols

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// Censys SMB1 Negotiate (single NT LM 0.12 dialect) seen on tcp/25026
// (https://ochi.mushmush.org/events/2df960ff-96a3-43ee-be6d-243a44c79ede)
var smb1CensysNegotiate = []byte{
	0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x43, 0xc8,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e,
	0x31, 0x32, 0x00,
}

func TestCatchAllRoutesOffPortSMB(t *testing.T) {
	names := dispatchTarget(t, "tcp", 25026, func(c net.Conn) {
		_, err := c.Write(smb1CensysNegotiate)
		require.NoError(t, err)

		// NBSS header, then a Negotiate response: \xffSMB, command 0x72, STATUS_SUCCESS
		hdr := make([]byte, 4)
		_, err = io.ReadFull(c, hdr)
		require.NoError(t, err)
		body := make([]byte, int(hdr[1])<<16|int(hdr[2])<<8|int(hdr[3]))
		_, err = io.ReadFull(c, body)
		require.NoError(t, err)
		require.Equal(t, []byte("\xffSMB"), body[:4])
		require.Equal(t, byte(0x72), body[4])
		require.Equal(t, []byte{0, 0, 0, 0}, body[5:9])
	})
	require.Equal(t, []string{"smb"}, names)
}

func TestCatchAllSMBLookalikeStaysTCP(t *testing.T) {
	names := dispatchTarget(t, "tcp", 25026, func(c net.Conn) {
		_, err := c.Write([]byte{0x00, 0x00, 0x00, 0x2f, 0xff, 'S', 'M', 'X', 0x72, 0x00})
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096)) // one random-bytes reply
	})
	require.Equal(t, []string{"tcp"}, names)
}
