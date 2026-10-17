package protocols

import (
	"bufio"
	"bytes"
	"net"
	"testing"

	"github.com/mushorg/glutton/protocols/tcp/hl7"
	"github.com/stretchr/testify/require"
)

// synthetic ADT^A04 in the HL7 v2.5 shape
var hl7ADT = []byte("MSH|^~\\&|REG|HOSP|LAB|LABFAC|20261017093000||ADT^A04|C17|P|2.5\rPID|1||42\r")

// sendHL7 writes msg and checks the reply acknowledges control ID C17.
func sendHL7(t *testing.T, msg []byte) func(net.Conn) {
	return func(c net.Conn) {
		_, err := c.Write(msg)
		require.NoError(t, err)
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		require.NoError(t, err)
		require.True(t, bytes.Contains(buf[:n], []byte("\rMSA|AA|C17\r")), "%q", buf[:n])
	}
}

func TestHL7TargetRoutesHL7(t *testing.T) {
	names := dispatchTarget(t, "hl7", 2575, sendHL7(t, hl7.Frame(hl7ADT)))
	require.Equal(t, []string{"hl7"}, names)

	// medpot-style unframed sender
	names = dispatchTarget(t, "hl7", 2575, sendHL7(t, hl7ADT))
	require.Equal(t, []string{"hl7"}, names)
}

func TestHL7TargetFallsBackToCatchAll(t *testing.T) {
	// other protocols reach their handlers through the catch-all dispatch
	// (HTTP/FHIR too; its session event is produced after an idle delay, so
	// a synchronous protocol proves the route here)
	names := dispatchTarget(t, "hl7", 2575, func(c net.Conn) {
		_, err := c.Write([]byte("*1\r\n$4\r\nPING\r\n"))
		require.NoError(t, err)
		line, err := bufio.NewReader(c).ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "+PONG\r\n", line)
	})
	require.Equal(t, []string{"redis"}, names)

	names = dispatchTarget(t, "hl7", 2575, func(c net.Conn) {
		_, err := c.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096)) // one random-bytes reply
	})
	require.Equal(t, []string{"tcp"}, names)
}

func TestCatchAllRoutesOffPortHL7(t *testing.T) {
	names := dispatchTarget(t, "tcp", 6661, sendHL7(t, hl7.Frame(hl7ADT)))
	require.Equal(t, []string{"hl7"}, names)
}

func TestCatchAllHL7LookalikeStaysTCP(t *testing.T) {
	names := dispatchTarget(t, "tcp", 6661, func(c net.Conn) {
		_, err := c.Write([]byte("MSHello there\r\n"))
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, []string{"tcp"}, names)
}
