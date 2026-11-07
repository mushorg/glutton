package banners

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// msmqEstablish is the 572-byte EstablishConnection 198.235.24.86 sent to
// tcp/1801 (2026-11-07): headers, ClientGuid, zero ServerGuid, TimeStamp,
// Flags 0x0310, then zero padding.
func msmqEstablish() []byte {
	b := make([]byte, 572)
	copy(b, mustHex("10000b004c494f523c020000ffffffff"))      // BaseHeader, PacketSize 572
	copy(b[16:], mustHex("00000200"))                         // InternalHeader, packet type 2
	copy(b[20:], mustHex("06553d5136dfc7409643175c3ce76caa")) // ClientGuid
	copy(b[52:], mustHex("d2291d0610030000"))                 // TimeStamp, Flags, Reserved
	return b
}

func TestForPayloadMSMQEstablish(t *testing.T) {
	data := msmqEstablish()
	resp, ok := ForPayload(data)
	require.True(t, ok)
	require.Equal(t, "msmq-establish", resp.Name)
	require.False(t, resp.Close)
	require.Len(t, resp.Data, 572)
	require.Equal(t, data[:36], resp.Data[:36], "headers and ClientGuid echoed")
	require.Equal(t, msmqServerGUID, resp.Data[36:52])
	require.Equal(t, data[52:], resp.Data[52:])
	require.Equal(t, make([]byte, 16), data[36:52], "request not modified")
}

func TestForPayloadMSMQConnectionParameters(t *testing.T) {
	data := mustHex("10000b004c494f5220000000ffffffff" + "00000300" +
		"30750000e8030000" + "00004000")
	resp, ok := ForPayload(data)
	require.True(t, ok)
	require.Equal(t, Response{Name: "msmq-connection-parameters", Data: data}, resp)
}

func TestForPayloadMSMQRejects(t *testing.T) {
	short := msmqEstablish()[:571]
	badSize := msmqEstablish()
	badSize[8] = 0x3d
	badSig := msmqEstablish()
	badSig[4] = 'X'
	badType := msmqEstablish()
	badType[18] = 0x05
	for _, data := range [][]byte{short, badSize, badSig, badType, []byte("LIOR")} {
		resp, ok := ForPayload(data)
		require.False(t, ok && (resp.Name == "msmq-establish" || resp.Name == "msmq-connection-parameters"), "%x", data[:min(len(data), 20)])
	}
}

func TestForPortMSMQ(t *testing.T) {
	resp, ok := ForPort(1801)
	require.True(t, ok)
	require.Equal(t, Response{Name: "msmq", Silent: true}, resp)
}
