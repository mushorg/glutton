package protocols

import (
	"net"
	"testing"

	"github.com/mushorg/glutton/protocols/tcp/nvms9000"
	"github.com/stretchr/testify/require"
)

// nvmsProbe is a queryBasicCfg request shaped like the one captured on
// tcp/8888 (Ochi event 8c21d002-4069-4f48-a464-ac3eb5742229).
func nvmsProbe() []byte {
	pad := func(s string) []byte { return append([]byte(s), make([]byte, 64-len(s))...) }
	body := append(pad("admin"), pad("queryBasicCfg")...)
	body = append(body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<request version=\"1.0\" systemType=\"NVMS-9000\" clientType=\"WEB\"/>\n"...)
	return nvms9000.Build(nvms9000.Header{Version: 0x01000004, Command: 0x091b, Unknown: 0x0102}, body)
}

func nvmsClient(t *testing.T, c net.Conn) {
	t.Helper()
	_, err := c.Write(nvmsProbe())
	require.NoError(t, err)
	frame, _, err := nvms9000.ReadFrame(c)
	require.NoError(t, err)
	require.Contains(t, string(frame.Body), `status="success"`)
}

func TestNVMSTargetRoutesFrame(t *testing.T) {
	names := dispatchTarget(t, "nvms9000", 6036, func(c net.Conn) { nvmsClient(t, c) })
	require.Equal(t, []string{"nvms9000"}, names)
}

func TestNVMSTargetFallsBackToTCP(t *testing.T) {
	names := dispatchTarget(t, "nvms9000", 6036, func(c net.Conn) {
		_, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, []string{"tcp"}, names)
}

func TestNVMSTargetSilentClientNoEvent(t *testing.T) {
	names := dispatchTarget(t, "nvms9000", 6036, func(net.Conn) {})
	require.Empty(t, names)
}

func TestCatchAllRoutesNVMS(t *testing.T) {
	ev := dispatchCatchAll(t, 8888, func(c net.Conn) { nvmsClient(t, c) })
	require.Equal(t, "nvms9000", ev.protocol)
	require.Equal(t, "queryBasicCfg", ev.frames[0]["command"])
	require.Equal(t, "admin", ev.frames[0]["username"])
}

func TestCatchAllNonNVMSStaysTCP(t *testing.T) {
	// the magic with an absurd length is not an NVMS-9000 frame
	ev := dispatchCatchAll(t, 8888, func(c net.Conn) {
		_, err := c.Write([]byte("11111111 hello\r\n"))
		require.NoError(t, err)
		_, _ = c.Read(make([]byte, 4096))
	})
	require.Equal(t, "tcp", ev.protocol)
}
