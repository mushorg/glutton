package tcp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/nettcp"
	"github.com/stretchr/testify/require"
)

const nettcpVia = "net.tcp://127.0.0.1:4026/Microsoft/VisualStudio/msvsmon"

// Captured from 205.210.31.108 on tcp/4026 (the whole preamble in one segment).
var nettcpCapturedPreamble = []byte{
	0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x37, 0x6e, 0x65, 0x74, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f,
	0x2f, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x34, 0x30, 0x32, 0x36, 0x2f,
	0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2f, 0x56, 0x69, 0x73, 0x75, 0x61, 0x6c,
	0x53, 0x74, 0x75, 0x64, 0x69, 0x6f, 0x2f, 0x6d, 0x73, 0x76, 0x73, 0x6d, 0x6f, 0x6e, 0x03, 0x08,
	0x0c,
}

// Captured from 216.25.90.83 on tcp/4025: the same msvsmon preamble with the
// Via naming port 4025.
var nettcpCaptured4025Preamble = []byte{
	0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x37, 0x6e, 0x65, 0x74, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f,
	0x2f, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x34, 0x30, 0x32, 0x35, 0x2f,
	0x4d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2f, 0x56, 0x69, 0x73, 0x75, 0x61, 0x6c,
	0x53, 0x74, 0x75, 0x64, 0x69, 0x6f, 0x2f, 0x6d, 0x73, 0x76, 0x73, 0x6d, 0x6f, 0x6e, 0x03, 0x08,
	0x0c,
}

func startNetTcp(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	return startNetTcpOnPort(t, 4026)
}

func startNetTcpOnPort(t *testing.T, port uint16) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleNetTcp(context.Background(), serverConn, connection.Metadata{TargetPort: port}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

func waitNetTcpEvent(t *testing.T, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	select {
	case ev := <-hp.produced:
		require.NoError(t, <-done)
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced NetTcp event")
		return producedTCP{}
	}
}

func preambleFrames() []parsedNetTcp {
	return []parsedNetTcp{
		{Direction: "read", Command: "Version", Version: "1.0", Payload: []byte{0x00, 0x01, 0x00}},
		{Direction: "read", Command: "Mode", Mode: "duplex", Payload: []byte{0x01, 0x02}},
		{Direction: "read", Command: "Via", Path: nettcpVia, Payload: append([]byte{0x02, 0x37}, nettcpVia...)},
		{Direction: "read", Command: "KnownEncoding", ContentType: "application/soap+msbinsession1", Payload: []byte{0x03, 0x08}},
		{Direction: "read", Command: "PreambleEnd", Payload: []byte{0x0c}},
		{Direction: "write", Command: "PreambleAck", Payload: []byte{0x0b}},
	}
}

func TestHandleNetTcpCapturedPreamble(t *testing.T) {
	client, hp, done := startNetTcp(t)
	_, err := client.Write(nettcpCapturedPreamble)
	require.NoError(t, err)

	ack := make([]byte, 1)
	_, err = io.ReadFull(client, ack)
	require.NoError(t, err)
	require.Equal(t, []byte{0x0b}, ack)

	// The client then sends an envelope and End; the server answers End.
	envelope := append([]byte{0x06, 0x04}, 0x56, 0x02, 0x0b, 0x01)
	_, err = client.Write(append(envelope, 0x07))
	require.NoError(t, err)
	end := make([]byte, 1)
	_, err = io.ReadFull(client, end)
	require.NoError(t, err)
	require.Equal(t, []byte{0x07}, end)

	ev := waitNetTcpEvent(t, hp, done)
	require.Equal(t, "nettcp", ev.protocol)
	require.Equal(t, []byte{0x00, 0x01, 0x00}, ev.payload)
	require.Equal(t, connection.EndHandlerClose, ev.endReason)
	want := append(preambleFrames(),
		parsedNetTcp{Direction: "read", Command: "SizedEnvelope", Payload: envelope},
		parsedNetTcp{Direction: "read", Command: "End", Payload: []byte{0x07}},
		parsedNetTcp{Direction: "write", Command: "End", Payload: []byte{0x07}},
	)
	require.Equal(t, want, ev.decoded)
	require.Empty(t, hp.produced)
}

func TestHandleNetTcpCaptured4025Preamble(t *testing.T) {
	client, hp, done := startNetTcpOnPort(t, 4025)
	_, err := client.Write(nettcpCaptured4025Preamble)
	require.NoError(t, err)

	ack := make([]byte, 1)
	_, err = io.ReadFull(client, ack)
	require.NoError(t, err)
	require.Equal(t, []byte{0x0b}, ack)
	require.NoError(t, client.Close())

	ev := waitNetTcpEvent(t, hp, done)
	require.Equal(t, "nettcp", ev.protocol)
	require.Equal(t, []byte{0x00, 0x01, 0x00}, ev.payload)
	via := "net.tcp://127.0.0.1:4025/Microsoft/VisualStudio/msvsmon"
	require.Equal(t, []parsedNetTcp{
		{Direction: "read", Command: "Version", Version: "1.0", Payload: []byte{0x00, 0x01, 0x00}},
		{Direction: "read", Command: "Mode", Mode: "duplex", Payload: []byte{0x01, 0x02}},
		{Direction: "read", Command: "Via", Path: via, Payload: append([]byte{0x02, 0x37}, via...)},
		{Direction: "read", Command: "KnownEncoding", ContentType: "application/soap+msbinsession1", Payload: []byte{0x03, 0x08}},
		{Direction: "read", Command: "PreambleEnd", Payload: []byte{0x0c}},
		{Direction: "write", Command: "PreambleAck", Payload: []byte{0x0b}},
	}, ev.decoded)
	require.Empty(t, hp.produced)
}

// Captured on tcp/9401 (sensor address scrubbed to 1.2.3.4, Via size byte
// adjusted from 0x1f to match): Version 1.0, duplex, Via,
// application/soap+msbinsession1, then an application/ssl-tls Upgrade Request.
var nettcpCaptured9401Preamble = []byte{
	0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x17, 0x6e, 0x65, 0x74, 0x2e, 0x74, 0x63, 0x70, 0x3a, 0x2f,
	0x2f, 0x31, 0x2e, 0x32, 0x2e, 0x33, 0x2e, 0x34, 0x3a, 0x39, 0x34, 0x30, 0x31, 0x2f, 0x03, 0x08,
	0x09, 0x13, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x73, 0x73,
	0x6c, 0x2d, 0x74, 0x6c, 0x73,
}

func TestHandleNetTcpSSLTLSUpgrade(t *testing.T) {
	client, hp, done := startNetTcpOnPort(t, 9401)
	_, err := client.Write(nettcpCaptured9401Preamble)
	require.NoError(t, err)

	resp := make([]byte, 1)
	_, err = io.ReadFull(client, resp)
	require.NoError(t, err)
	require.Equal(t, []byte{0x0a}, resp)

	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: "wcf.example.com"})
	require.NoError(t, tc.Handshake())

	// Inside TLS: PreambleEnd gets PreambleAck, End gets End.
	_, err = tc.Write([]byte{0x0c})
	require.NoError(t, err)
	_, err = io.ReadFull(tc, resp)
	require.NoError(t, err)
	require.Equal(t, []byte{0x0b}, resp)
	_, err = tc.Write([]byte{0x07})
	require.NoError(t, err)
	_, err = io.ReadFull(tc, resp)
	require.NoError(t, err)
	require.Equal(t, []byte{0x07}, resp)

	ev := waitNetTcpEvent(t, hp, done)
	require.Equal(t, "nettcp", ev.protocol)
	require.NotNil(t, ev.tls)
	require.Equal(t, "wcf.example.com", ev.tls.ServerName)
	frames := ev.decoded.([]parsedNetTcp)
	require.Len(t, frames, 11)
	via := "net.tcp://1.2.3.4:9401/"
	require.Equal(t, []parsedNetTcp{
		{Direction: "read", Command: "Version", Version: "1.0", Payload: []byte{0x00, 0x01, 0x00}},
		{Direction: "read", Command: "Mode", Mode: "duplex", Payload: []byte{0x01, 0x02}},
		{Direction: "read", Command: "Via", Path: via, Payload: append([]byte{0x02, 0x17}, via...)},
		{Direction: "read", Command: "KnownEncoding", ContentType: "application/soap+msbinsession1", Payload: []byte{0x03, 0x08}},
		{Direction: "read", Command: "UpgradeRequest", ContentType: "application/ssl-tls", Payload: nettcpCaptured9401Preamble[32:]},
		{Direction: "write", Command: "UpgradeResponse", Payload: []byte{0x0a}},
	}, frames[:6])
	require.Equal(t, "tls", frames[6].Command)
	require.Equal(t, "read", frames[6].Direction)
	require.Equal(t, "wcf.example.com", frames[6].ServerName)
	require.Equal(t, byte(0x16), frames[6].Payload[0])
	require.Equal(t, []parsedNetTcp{
		{Direction: "read", Command: "PreambleEnd", TLS: true, Payload: []byte{0x0c}},
		{Direction: "write", Command: "PreambleAck", TLS: true, Payload: []byte{0x0b}},
		{Direction: "read", Command: "End", TLS: true, Payload: []byte{0x07}},
		{Direction: "write", Command: "End", TLS: true, Payload: []byte{0x07}},
	}, frames[7:])
}

func TestHandleNetTcpUpgradeHandshakeFails(t *testing.T) {
	client, hp, done := startNetTcpOnPort(t, 9401)
	_, err := client.Write(nettcpCaptured9401Preamble)
	require.NoError(t, err)
	resp := make([]byte, 1)
	_, err = io.ReadFull(client, resp)
	require.NoError(t, err)
	require.Equal(t, []byte{0x0a}, resp)
	require.NoError(t, client.Close())

	ev := waitNetTcpEvent(t, hp, done)
	require.Nil(t, ev.tls)
	frames := ev.decoded.([]parsedNetTcp)
	require.Len(t, frames, 7)
	require.Equal(t, parsedNetTcp{Direction: "read", Command: "tls"}, frames[6])
}

func TestHandleNetTcpEarlyDisconnect(t *testing.T) {
	client, hp, done := startNetTcp(t)
	// Version, Mode, then half a Via record.
	_, err := client.Write(nettcpCapturedPreamble[:10])
	require.NoError(t, err)
	require.NoError(t, client.Close())

	ev := waitNetTcpEvent(t, hp, done)
	require.Equal(t, "nettcp", ev.protocol)
	require.Equal(t, []parsedNetTcp{
		{Direction: "read", Command: "Version", Version: "1.0", Payload: []byte{0x00, 0x01, 0x00}},
		{Direction: "read", Command: "Mode", Mode: "duplex", Payload: []byte{0x01, 0x02}},
		{Direction: "read", Command: "Via", Payload: []byte{0x02, 0x37}, Truncated: true},
	}, ev.decoded)
}

func TestHandleNetTcpMalformed(t *testing.T) {
	client, hp, done := startNetTcp(t)
	// A TLS ClientHello is not an MS-NMF record.
	_, err := client.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05})
	require.NoError(t, err)

	ev := waitNetTcpEvent(t, hp, done)
	require.Equal(t, []parsedNetTcp{
		{Direction: "read", Command: "0x16", Payload: []byte{0x16}},
	}, ev.decoded)
}

func TestHandleNetTcpUnsupportedVersion(t *testing.T) {
	client, hp, done := startNetTcp(t)
	_, err := client.Write([]byte{0x00, 0x02, 0x00})
	require.NoError(t, err)
	buf, err := io.ReadAll(client)
	require.NoError(t, err)
	fault := nettcp.FaultRecord(nettcp.FaultUnsupportedVersion)
	require.Equal(t, fault, buf)

	ev := waitNetTcpEvent(t, hp, done)
	require.Equal(t, []parsedNetTcp{
		{Direction: "read", Command: "Version", Version: "2.0", Payload: []byte{0x00, 0x02, 0x00}},
		{Direction: "write", Command: "Fault", Status: "UnsupportedVersion", Fault: "http://schemas.microsoft.com/ws/2006/05/framing/faults/UnsupportedVersion", Payload: fault},
	}, ev.decoded)
}

func TestHandleNetTcpOversizeVia(t *testing.T) {
	client, hp, done := startNetTcp(t)
	data := append([]byte{0x00, 0x01, 0x00, 0x01, 0x02, 0x02}, nettcp.EncodeSize(maxNetTcpRecordSize+10)...)
	go func() {
		_, _ = client.Write(data)
		_, _ = client.Write(make([]byte, maxNetTcpRecordSize+10))
	}()

	ev := waitNetTcpEvent(t, hp, done)
	frames := ev.decoded.([]parsedNetTcp)
	require.Len(t, frames, 3)
	require.Equal(t, "Via", frames[2].Command)
	require.True(t, frames[2].Truncated)
	require.Len(t, frames[2].Path, maxNetTcpRecordSize)
}
