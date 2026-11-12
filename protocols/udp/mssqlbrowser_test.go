package udp

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/mssqlbrowser"
)

// Captured datagram (205.210.31.194 -> udp/1434, 2026-11-12T19:37:33Z):
// CLNT_BCAST_EX, base64 "Ag==".
var mssqlBrowserBcast = []byte{0x02}

func withMSSQLBrowserPersona(t *testing.T) {
	t.Helper()
	orig := mssqlBrowserPersona
	mssqlBrowserPersona = func() mssqlbrowser.Persona {
		return mssqlbrowser.Persona{Server: "WIN-SQL01", Instance: "MSSQLSERVER", Version: "15.0.2000.5", TCPPort: 1433}
	}
	t.Cleanup(func() { mssqlBrowserPersona = orig })
}

func runMSSQLBrowser(t *testing.T, h *recordingHoneypot, data []byte) []parsedMSSQLBrowser {
	t.Helper()
	src := &net.UDPAddr{IP: net.ParseIP("205.210.31.194"), Port: 54191}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1434}
	require.NoError(t, HandleMSSQLBrowser(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, "mssql_browser", h.produced[0].handler)
	return h.produced[0].decoded.([]parsedMSSQLBrowser)
}

func TestHandleMSSQLBrowserBroadcast(t *testing.T) {
	withMSSQLBrowserPersona(t)
	h := &recordingHoneypot{}
	events := runMSSQLBrowser(t, h, mssqlBrowserBcast)

	desc := `ServerName;WIN-SQL01;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.2000.5;tcp;1433;np;\\WIN-SQL01\pipe\sql\query;;`
	want := append([]byte{0x05, byte(len(desc)), 0x00}, desc...)
	require.Equal(t, [][]byte{want}, h.replies)
	require.Equal(t, mssqlBrowserBcast, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
	require.Equal(t, []parsedMSSQLBrowser{
		{Direction: "read", Command: "CLNT_BCAST_EX", Payload: mssqlBrowserBcast},
		{Direction: "write", Command: "CLNT_BCAST_EX", Status: "SVR_RESP", Payload: want},
	}, events)
}

func TestHandleMSSQLBrowserInstance(t *testing.T) {
	withMSSQLBrowserPersona(t)
	data := append([]byte{0x04}, "MSSQLSERVER\x00"...)
	h := &recordingHoneypot{}
	events := runMSSQLBrowser(t, h, data)
	require.Len(t, h.replies, 1)
	require.Len(t, events, 2)
	require.Equal(t, "MSSQLSERVER", events[0].Instance)
	require.Equal(t, "SVR_RESP", events[1].Status)

	h = &recordingHoneypot{}
	events = runMSSQLBrowser(t, h, append([]byte{0x04}, "SQLEXPRESS\x00"...))
	require.Empty(t, h.replies)
	require.Equal(t, []parsedMSSQLBrowser{
		{Direction: "read", Command: "CLNT_UCAST_INST", Instance: "SQLEXPRESS", Payload: append([]byte{0x04}, "SQLEXPRESS\x00"...)},
	}, events)
}

func TestHandleMSSQLBrowserUnknown(t *testing.T) {
	withMSSQLBrowserPersona(t)
	for _, data := range [][]byte{
		{},
		[]byte("\r\n\r\n"),
		bytes.Repeat([]byte{0x02}, 2000),
	} {
		h := &recordingHoneypot{}
		events := runMSSQLBrowser(t, h, data)
		require.Empty(t, h.replies)
		require.Len(t, events, 1)
		require.Empty(t, events[0].Command)
		require.Equal(t, len(data) > maxMSSQLBrowserPayload, events[0].Truncated)
		require.LessOrEqual(t, len(events[0].Payload), maxMSSQLBrowserPayload)
	}
}

func TestHandleMSSQLBrowserReplyError(t *testing.T) {
	withMSSQLBrowserPersona(t)
	h := &failingReplyHoneypot{}
	src := &net.UDPAddr{IP: net.ParseIP("205.210.31.194"), Port: 54191}
	dst := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1434}
	require.NoError(t, HandleMSSQLBrowser(context.Background(), src, dst, mssqlBrowserBcast, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, connection.EndWriteError, h.produced[0].endReason)
}
