package banners

import (
	"bytes"
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

	_, ok := ForPort(9999)
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
