package banners

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestForPort(t *testing.T) {
	cases := []struct {
		port          uint16
		name          string
		serverFirst   bool
		greetWhenIdle bool
		prefix        []byte
	}{
		{22, "ssh", true, false, []byte("SSH-2.0-OpenSSH_")},
		{2222, "ssh", true, false, []byte("SSH-2.0-OpenSSH_")},
		{110, "pop3", true, false, []byte("+OK ")},
		{5900, "rfb", true, false, []byte("RFB 003.008\n")},
		{80, "http", false, false, []byte("HTTP/1.1 200 OK\r\n")},
		{135, "dcerpc-bind-ack", false, false, []byte{0x05, 0x00, 0x0c, 0x03}},
		{139, "netbios-session", false, false, []byte{0x82, 0x00, 0x00, 0x00}},
		{1433, "mssql-prelogin", false, false, []byte{0x04, 0x01, 0x00, 0x25}},
		{4899, "radmin", false, false, []byte{0x01, 0x00, 0x00, 0x00, 0x25}},
		{8009, "ajp-404", false, false, []byte("AB\x00\x36\x04\x01\x94")},
		{8126, "statsd-stats", false, false, []byte("uptime: ")},
		{4444, "cmd-shell", false, true, []byte("Microsoft Windows [Version 5.2.3790]\r\n")},
	}
	for _, c := range cases {
		resp, ok := ForPort(c.port)
		require.True(t, ok, c.port)
		require.Equal(t, c.name, resp.Name, c.port)
		require.Equal(t, c.serverFirst, resp.ServerFirst, c.port)
		require.Equal(t, c.greetWhenIdle, resp.GreetWhenIdle, c.port)
		require.True(t, bytes.HasPrefix(resp.Data, c.prefix), "%d: %q", c.port, resp.Data)
	}

	resp, ok := ForPort(389)
	require.True(t, ok)
	require.Equal(t, Response{Name: "ldap", Silent: true}, resp)

	_, ok = ForPort(9999)
	require.False(t, ok)
}

func TestBinaryResponseLengths(t *testing.T) {
	// lengths of the honeytrap response files
	require.Len(t, dcerpcBindAck, 60)
	require.Len(t, mssqlPrelogin, 37)
	require.Len(t, radminReply, 46)
	require.Len(t, ajp404, 785)
	// TDS header length field covers the whole packet
	require.Equal(t, len(mssqlPrelogin), int(mssqlPrelogin[2])<<8|int(mssqlPrelogin[3]))
}

func TestTextBannersUseCRLF(t *testing.T) {
	for _, b := range [][]byte{sshBanner, pop3Banner} {
		require.True(t, bytes.HasSuffix(b, []byte("\r\n")), "%q", b)
		require.Equal(t, 1, bytes.Count(b, []byte("\n")), "%q", b)
	}
}

func TestCmdShellBanner(t *testing.T) {
	// bare LFs are what nmap flags as a honeyd cmd.exe emulation
	require.Equal(t, bytes.Count(cmdShellBanner, []byte("\n")), bytes.Count(cmdShellBanner, []byte("\r\n")))
	// the prompt ends at '>' with no trailing space or newline
	require.True(t, bytes.HasSuffix(cmdShellBanner, []byte("C:\\WINDOWS\\system32>")), "%q", cmdShellBanner)
}

func TestHTTPResponse(t *testing.T) {
	prev := now
	now = func() time.Time { return time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = prev })

	out := string(httpResponse())
	head, body, ok := strings.Cut(out, "\r\n\r\n")
	require.True(t, ok)
	require.Contains(t, head, "Date: Tue, 06 Oct 2026 12:00:00 GMT")
	require.Contains(t, head, "Content-Length: "+strconv.Itoa(len(body)))
	require.NotContains(t, strings.ReplaceAll(head, "\r\n", ""), "\n", "bare LF in headers")
}

func TestStatsdStats(t *testing.T) {
	prevNow, prevStart := now, statsdStart
	now = func() time.Time { return time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC) }
	statsdStart = now().Add(-90 * time.Second)
	t.Cleanup(func() { now, statsdStart = prevNow, prevStart })

	// 2026-10-06T12:00:00Z is Unix 1791288000
	require.Equal(t, "uptime: 90\n"+
		"messages.last_msg_seen: 5\n"+
		"messages.bad_lines_seen: 0\n"+
		"graphite.last_flush: 0\n"+
		"graphite.last_exception: 90\n"+
		"graphite.flush_time: 0\n"+
		"graphite.flush_length: 1400\n"+
		"END\n\n", string(statsdStats()))
}

func TestForPayload(t *testing.T) {
	resp, ok := ForPayload([]byte("SSH-2.0-Go\r\n"))
	require.True(t, ok)
	require.Equal(t, "ssh", resp.Name)
	require.Equal(t, sshBanner, resp.Data)

	// TLS 1.2 ClientHello record header
	resp, ok = ForPayload([]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01})
	require.True(t, ok)
	require.Equal(t, "tls-alert", resp.Name)
	require.Equal(t, []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}, resp.Data)

	// X11 setup from Ochi event bf678cc5-ae8d-4ea2-8d97-02ca98d6e37c (nmap X11Probe)
	resp, ok = ForPayload([]byte{0x6c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	require.True(t, ok)
	require.Equal(t, "x11-denied", resp.Name)
	require.Equal(t, append([]byte{0x00, 0x16, 0x0b, 0x00, 0x00, 0x00, 0x06, 0x00},
		"No protocol specified\n\x00\x00"...), resp.Data)

	resp, ok = ForPayload([]byte{0x42, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x12, 0x00, 0x10, 0x00, 0x00})
	require.True(t, ok)
	require.Equal(t, "x11-denied", resp.Name)
	require.Equal(t, append([]byte{0x00, 0x16, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x06},
		"No protocol specified\n\x00\x00"...), resp.Data)

	for _, data := range [][]byte{
		nil, []byte("GET / HTTP/1.0\r\n\r\n"), {0x16, 0x03}, {0x16, 0x02, 0x00},
		[]byte("lol\r\nlol\r\nlol\r\n"),
		{0x6c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00},                         // short
		{0x6c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // major 10
		{0x6c, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // wrong byte order
		{0x6c, 0x01, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // unused byte set
	} {
		_, ok := ForPayload(data)
		require.False(t, ok, "%q", data)
	}
}

// censysH2 is the h2c preface + SETTINGS from Ochi event
// 2fa1bb07-466c-4764-851d-096aeb5ce474 (Censys, tcp/44818).
const censysH2 = "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a" +
	"00001804000000000000020000000000040000426800060004000000030000000a"

func TestForPayloadHTTP2Preface(t *testing.T) {
	data, err := hex.DecodeString(censysH2)
	require.NoError(t, err)
	resp, ok := ForPayload(data)
	require.True(t, ok)
	require.Equal(t, Response{Name: "http2-settings", Data: h2Reply}, resp)

	// the bare preface is enough, a partial one is not
	_, ok = ForPayload(h2Preface)
	require.True(t, ok)
	for _, data := range [][]byte{data[:20], []byte("PRI * HTTP/1.1\r\n\r\n")} {
		_, ok := ForPayload(data)
		require.False(t, ok, "%q", data)
	}
}

func TestHTTP2ReplyFrames(t *testing.T) {
	type frame struct {
		typ, flags byte
		stream     uint32
		payload    []byte
	}
	var frames []frame
	for b := h2Reply; len(b) > 0; {
		require.GreaterOrEqual(t, len(b), 9)
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		require.GreaterOrEqual(t, len(b), 9+n)
		frames = append(frames, frame{b[3], b[4], binary.BigEndian.Uint32(b[5:9]), b[9 : 9+n]})
		b = b[9+n:]
	}
	require.Len(t, frames, 4)
	for _, f := range frames {
		require.Zero(t, f.stream)
	}
	// SETTINGS, WINDOW_UPDATE, SETTINGS ACK, GOAWAY
	require.Equal(t, []byte{0x04, 0x08, 0x04, 0x07}, []byte{frames[0].typ, frames[1].typ, frames[2].typ, frames[3].typ})
	require.Zero(t, frames[0].flags)
	require.Zero(t, len(frames[0].payload)%6)
	require.Equal(t, byte(0x01), frames[2].flags)
	require.Empty(t, frames[2].payload)
	require.Equal(t, make([]byte, 8), frames[3].payload) // last stream 0, NO_ERROR
}
