package producer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/rules"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	p, err := New("test", "v1.2.3")
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equal(t, "v1.2.3", p.sensorVersion)
}

func TestProducerLog(t *testing.T) {
	p, err := New("test", "v0.0.0")
	require.NoError(t, err)
	require.NotNil(t, p)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NotNil(t, l)
	defer l.Close()
	conn, err := net.Dial(l.Addr().Network(), l.Addr().String())
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	md := connection.Metadata{
		Rule: &rules.Rule{},
	}

	viper.Set("producers.http.enabled", true)

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer svr.Close()

	viper.Set("producers.http.remote", svr.URL)

	err = p.LogTCP("test", conn, md, []byte{123}, nil)
	require.NoError(t, err)

	err = p.LogUDP("test", &net.UDPAddr{}, &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 53}, md, []byte{123}, nil)
	require.NoError(t, err)
}

func TestMakeEventTCPEnvelope(t *testing.T) {
	p, err := New("sensor-1", "v9.9.9")
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	conn, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	started := time.Now().UTC().Add(-1500 * time.Millisecond)
	md := connection.Metadata{
		Added:      started,
		TargetPort: 445,
		TargetIP:   "192.0.2.10",
		EndReason:  connection.EndClientClose,
		Rule:       &rules.Rule{Name: "SMB", Match: "tcp dst port 445"},
	}
	payload := []byte("hello")
	decoded := []struct {
		Direction string
		Payload   []byte
	}{{Direction: "read", Payload: payload}, {Direction: "write", Payload: []byte("ok")}}

	ev, err := p.makeEventTCP("smb", conn, md, payload, decoded)
	require.NoError(t, err)
	require.Equal(t, "tcp", ev.Transport)
	require.Equal(t, "smb", ev.Handler)
	require.Equal(t, "sensor-1", ev.SensorID)
	require.Equal(t, "v9.9.9", ev.SensorVersion)
	require.Equal(t, "192.0.2.10", ev.DstHost)
	require.Equal(t, uint16(445), ev.DstPort)
	require.Equal(t, "SMB", ev.RuleName)
	require.Equal(t, "Rule: tcp dst port 445", ev.Rule)
	require.Equal(t, connection.EndClientClose, ev.EndReason)
	require.Equal(t, 2, ev.FrameCount)
	sum := sha256.Sum256(payload)
	require.Equal(t, hex.EncodeToString(sum[:]), ev.PayloadHash)
	require.False(t, ev.StartedAt.IsZero())
	require.GreaterOrEqual(t, ev.DurationMs, int64(1000))
}

func TestMakeEventUDPEnvelope(t *testing.T) {
	p, err := New("sensor-1", "v9.9.9")
	require.NoError(t, err)
	src := &net.UDPAddr{IP: net.ParseIP("203.0.113.8"), Port: 1234}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 53}
	md := connection.Metadata{TargetPort: 53}
	decoded := []struct{ Direction string }{{Direction: "read"}}

	ev, err := p.makeEventUDP("udp", src, dst, md, []byte{1, 2, 3}, decoded)
	require.NoError(t, err)
	require.Equal(t, "udp", ev.Transport)
	require.Equal(t, "203.0.113.8", ev.SrcHost)
	require.Equal(t, "198.51.100.9", ev.DstHost)
	require.Equal(t, uint16(53), ev.DstPort)
	require.Equal(t, 1, ev.FrameCount)
	require.Equal(t, "v9.9.9", ev.SensorVersion)
}

func TestSanitizeDecodedPayload(t *testing.T) {
	type frame struct {
		Direction string
		Path      string
		Payload   []byte
	}
	in := []frame{{
		Direction: "read",
		Path:      `\\192.0.2.1\IPC$`,
		Payload:   []byte("hit 192.0.2.1 here"),
	}}
	out := SanitizeDecoded(in, func(b []byte) []byte {
		return bytes.ReplaceAll(b, []byte("192.0.2.1"), []byte("1.2.3.4"))
	}).([]frame)
	require.Equal(t, `\\1.2.3.4\IPC$`, out[0].Path)
	require.Equal(t, []byte("hit 1.2.3.4 here"), out[0].Payload)
	require.Contains(t, string(in[0].Payload), "192.0.2.1")
}
