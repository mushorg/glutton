package banners

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenWireWireFormatInfo(t *testing.T) {
	b := openwireWireFormatInfo
	// size prefix covers everything after it
	require.Equal(t, uint32(len(b)-4), binary.BigEndian.Uint32(b[:4]))
	require.Equal(t, byte(1), b[4], "WIREFORMAT_INFO type")
	require.Equal(t, []byte("ActiveMQ"), b[5:13])
	require.Equal(t, uint32(12), binary.BigEndian.Uint32(b[13:17]))
	require.Equal(t, byte(1), b[17], "properties present")
	require.Equal(t, uint32(len(b)-22), binary.BigEndian.Uint32(b[18:22]))
	require.Equal(t, uint32(len(openwireProperties)), binary.BigEndian.Uint32(b[22:26]))

	// nmap apachemq match lines, atomic groups as plain groups for RE2
	full := regexp.MustCompile(`(?s)^\x00\x00..\x01ActiveMQ\x00\x00\x00.\x01\x00\x00(?:.*?\x0cProviderName)\t\x00\x08ActiveMQ(?:.*?\x0fPlatformDetails)\t..JVM: (\d[^,]*), [^,]*, Oracle Corporation, OS: Linux, (\d\.[\d.]+)[^,]*, ([\w_-]+)(?:.*?\x0fProviderVersion)\t..(\d[\w._-]*)`)
	m := full.FindSubmatch(b)
	require.NotNil(t, m)
	require.Equal(t, "11.0.21", string(m[1]))
	require.Equal(t, "5.15.0", string(m[2]))
	require.Equal(t, "amd64", string(m[3]))
	require.Equal(t, "5.18.2", string(m[4]))
	require.Regexp(t, regexp.MustCompile(`(?s)^\x00\x00..\x01ActiveMQ\x00\x00\x00.\x01\x00\x00.*\x0cMaxFrameSize\x06`), string(b))

	require.False(t, bytes.Contains(bytes.ToLower(b), []byte("glutton")))
	require.False(t, bytes.Contains(bytes.ToLower(b), []byte("honeypot")))
}

func TestOpenWireFollowUp(t *testing.T) {
	for _, in := range [][]byte{[]byte("\n"), openwireWireFormatInfo, {0, 0, 0, 5, 0x1f}} {
		resp, ok := OpenWireFollowUp(in)
		require.True(t, ok)
		require.Equal(t, Response{Name: "openwire", NoReply: true, Close: true}, resp)
	}
}
