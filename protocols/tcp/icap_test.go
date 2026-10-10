package tcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/icap"
	"github.com/stretchr/testify/require"
)

// read frame 1 of https://ochi.mushmush.org/events/9b3f8947-17bb-4c7f-af45-6ca88717dc1e (tcp/1344)
var icapRead1 = []byte("OPTIONS icap://1.2.3.4:1344/ ICAP/1.0\r\nHost: 1.2.3.4:1344\r\n\r\n")

const icapHTTPReq = "POST /upload HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 11\r\n\r\n"

// synthetic REQMOD with a 4-byte preview, RFC 3507 §4.8.3 shape
var icapReqmodPreview = []byte("REQMOD icap://icap.example.org/avscan ICAP/1.0\r\n" +
	"Host: icap.example.org\r\nUser-Agent: test-client\r\nAllow: 204\r\nPreview: 4\r\n" +
	fmt.Sprintf("Encapsulated: req-hdr=0, req-body=%d\r\n\r\n", len(icapHTTPReq)) +
	icapHTTPReq + "4\r\nhell\r\n0\r\n\r\n")

var icapReqmodRest = []byte("7\r\no world\r\n0\r\n\r\n")

var icapDate = time.Date(2026, 10, 10, 21, 38, 45, 0, time.UTC)

func startICAP(t *testing.T) (net.Conn, *fakeHoneypot, chan error, *[][]byte) {
	t.Helper()
	stored := &[][]byte{}
	prev := storeICAP
	storeICAP = func(data []byte) (string, error) {
		*stored = append(*stored, append([]byte(nil), data...))
		return "hash", nil
	}
	t.Cleanup(func() { storeICAP = prev })

	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	server := newICAPServer(serverConn)
	server.now = func() time.Time { return icapDate }
	done := make(chan error, 1)
	go func() {
		done <- handleICAP(context.Background(), server, connection.Metadata{TargetPort: 1344}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done, stored
}

// readICAPReply reads one ICAP response head plus any echoed body.
func readICAPReply(t *testing.T, r *bufio.Reader) []byte {
	t.Helper()
	var out []byte
	for {
		line, err := r.ReadBytes('\n')
		require.NoError(t, err)
		out = append(out, line...)
		if string(line) == "\r\n" {
			return out
		}
	}
}

func waitICAP(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "icap", produced.protocol)
	return produced, err
}

func TestHandleICAPOptionsProbe(t *testing.T) {
	client, hp, done, _ := startICAP(t)
	r := bufio.NewReader(client)

	_, err := client.Write(icapRead1)
	require.NoError(t, err)
	reply := readICAPReply(t, r)
	require.Equal(t, icap.BuildOptions(icapPersona(), icapDate), reply)
	require.Contains(t, string(reply), "ICAP/1.0 200 OK\r\nMethods: RESPMOD, REQMOD\r\n")

	require.NoError(t, client.Close())
	produced, err := waitICAP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedICAP{
		{Direction: "read", Command: "OPTIONS", Path: "/", Payload: icapRead1},
		{Direction: "write", Status: "200", Payload: reply},
	}, produced.decoded)
}

func TestHandleICAPReqmodPreviewContinue(t *testing.T) {
	client, hp, done, stored := startICAP(t)
	r := bufio.NewReader(client)

	_, err := client.Write(icapRead1)
	require.NoError(t, err)
	options := readICAPReply(t, r)

	_, err = client.Write(icapReqmodPreview)
	require.NoError(t, err)
	cont := readICAPReply(t, r)
	require.Equal(t, "ICAP/1.0 100 Continue\r\n\r\n", string(cont))

	_, err = client.Write(icapReqmodRest)
	require.NoError(t, err)
	final := readICAPReply(t, r)
	require.Equal(t, icap.BuildStatus(204, icapPersona(), icapDate), final)

	require.NoError(t, client.Close())
	produced, err := waitICAP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("hello world")}, *stored)
	require.Equal(t, []parsedICAP{
		{Direction: "read", Command: "OPTIONS", Path: "/", Payload: icapRead1},
		{Direction: "write", Status: "200", Payload: options},
		{
			Direction: "read", Command: "REQMOD", Path: "/avscan", UserAgent: "test-client",
			Encapsulated: fmt.Sprintf("req-hdr=0, req-body=%d", len(icapHTTPReq)), Preview: "4",
			HTTPRequest: "POST /upload HTTP/1.1", Payload: icapReqmodPreview,
		},
		{Direction: "write", Status: "100", Payload: cont},
		{Direction: "read", Command: "REQMOD", Path: "/avscan", PayloadHash: "hash", Payload: icapReqmodRest},
		{Direction: "write", Status: "204", Payload: final},
	}, produced.decoded)
}

func TestHandleICAPRespmodEchoWithoutAllow204(t *testing.T) {
	client, hp, done, _ := startICAP(t)
	resHdr := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
	wire := "RESPMOD icap://icap.example.org/echo ICAP/1.0\r\nHost: icap.example.org\r\nConnection: close\r\n" +
		fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n\r\n", len(resHdr)) +
		resHdr + "3\r\nabc\r\n0\r\n\r\n"
	_, err := client.Write([]byte(wire))
	require.NoError(t, err)
	reply, err := io.ReadAll(client)
	require.NoError(t, err)
	require.Contains(t, string(reply), "ICAP/1.0 200 OK\r\n")
	require.Contains(t, string(reply), fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d\r\n\r\n", len(resHdr))+resHdr+"3\r\nabc\r\n0\r\n\r\n")

	produced, err := waitICAP(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedICAP)
	require.Len(t, frames, 2)
	require.Equal(t, "HTTP/1.1 200 OK", frames[0].HTTPStatus)
	require.Equal(t, "hash", frames[0].PayloadHash)
	require.Equal(t, "200", frames[1].Status)
}

func TestHandleICAPUnknownMethod(t *testing.T) {
	client, hp, done, _ := startICAP(t)
	r := bufio.NewReader(client)
	_, err := client.Write([]byte("PUT icap://x/ ICAP/1.0\r\n\r\n"))
	require.NoError(t, err)
	reply := readICAPReply(t, r)
	require.Contains(t, string(reply), "ICAP/1.0 405 Method not allowed for service\r\n")

	require.NoError(t, client.Close())
	produced, err := waitICAP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, "405", produced.decoded.([]parsedICAP)[1].Status)
}

func TestHandleICAPMalformedGets400(t *testing.T) {
	client, hp, done, _ := startICAP(t)
	r := bufio.NewReader(client)
	_, err := client.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	require.NoError(t, err)
	reply := readICAPReply(t, r)
	require.Equal(t, icap.BuildStatus(400, icapPersona(), icapDate), reply)

	produced, err := waitICAP(t, hp, done)
	require.ErrorIs(t, err, icap.ErrMalformed)
	require.Equal(t, connection.EndReadError, produced.endReason)
	require.Equal(t, []parsedICAP{
		{Direction: "read", Payload: []byte("GET / HTTP/1.1\r\n")},
		{Direction: "write", Status: "400", Payload: reply},
	}, produced.decoded)
}

func TestHandleICAPEarlyDisconnectStillProduces(t *testing.T) {
	client, hp, done, _ := startICAP(t)
	require.NoError(t, client.Close())

	produced, err := waitICAP(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleICAPPartialRequestStored(t *testing.T) {
	client, hp, done, _ := startICAP(t)
	partial := icapRead1[:45]
	_, err := client.Write(partial)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced, err := waitICAP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedICAP{{Direction: "read", Command: "OPTIONS", Path: "/", Payload: partial}}, produced.decoded)
}

func TestHandleICAPOversizeBodyTruncated(t *testing.T) {
	client, hp, done, stored := startICAP(t)
	r := bufio.NewReader(client)
	size := icapMaxBody + 100
	head := fmt.Sprintf("REQMOD icap://x/ ICAP/1.0\r\nAllow: 204\r\nEncapsulated: req-body=0\r\n\r\n%x\r\n", size)
	go func() {
		_, _ = client.Write([]byte(head))
		_, _ = client.Write(make([]byte, size))
		_, _ = client.Write([]byte("\r\n0\r\n\r\n"))
	}()
	reply := readICAPReply(t, r)
	require.Contains(t, string(reply), "ICAP/1.0 204 Unmodified\r\n")

	require.NoError(t, client.Close())
	produced, err := waitICAP(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedICAP)
	require.True(t, frames[0].Truncated)
	require.Len(t, frames[0].Payload, len(head)+icapMaxBody+len("\r\n0\r\n\r\n"))
	require.Len(t, (*stored)[0], icapMaxBody)
}
