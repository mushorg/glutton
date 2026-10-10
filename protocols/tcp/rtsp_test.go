package tcp

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/rtsp"
	"github.com/stretchr/testify/require"
)

// read frame 1 of ochi event f30046fd-0bb9-4f7c-b9c3-e25df4ddcff5 (tcp/10554)
var rtspRead1 = []byte("OPTIONS rtsp://1.2.3.4:10554 RTSP/1.0\r\nCSeq: 1\r\n\r\n")

// synthetic follow-ups in the shape of common camera brute-forcers
var (
	rtspDescribe      = []byte("DESCRIBE rtsp://1.2.3.4:10554/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: LibVLC/3.0.18 (LIVE555 Streaming Media v2016.11.28)\r\nAccept: application/sdp\r\n\r\n")
	rtspDescribeBasic = []byte("DESCRIBE rtsp://1.2.3.4:10554/Streaming/Channels/101 RTSP/1.0\r\nCSeq: 3\r\nAuthorization: Basic YWRtaW46MTIzNDU=\r\nAccept: application/sdp\r\n\r\n")
)

func fixedRTSPResponder() *rtsp.Responder {
	return &rtsp.Responder{
		Server: "Rtsp Server/3.0",
		Realm:  "Login to 7K02D8APAZ1C3F9",
		Nonce:  "00112233445566778899aabbccddeeff",
		Now:    func() time.Time { return time.Date(2026, 10, 10, 21, 44, 20, 0, time.UTC) },
	}
}

func startRTSP(t *testing.T) (net.Conn, *bufio.Reader, *fakeHoneypot, chan error) {
	t.Helper()
	prev := newRTSPResponder
	newRTSPResponder = fixedRTSPResponder
	t.Cleanup(func() { newRTSPResponder = prev })

	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRTSP(context.Background(), serverConn, connection.Metadata{TargetPort: 10554}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, bufio.NewReader(client), hp, done
}

// readRTSPReply reads one header-only reply.
func readRTSPReply(t *testing.T, r *bufio.Reader) []byte {
	t.Helper()
	var buf bytes.Buffer
	for {
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		buf.WriteString(line)
		if line == "\r\n" {
			return buf.Bytes()
		}
	}
}

func waitRTSP(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "rtsp", produced.protocol)
	return produced, err
}

func TestHandleRTSPSession(t *testing.T) {
	client, r, hp, done := startRTSP(t)

	_, err := client.Write(rtspRead1)
	require.NoError(t, err)
	options := readRTSPReply(t, r)
	require.Equal(t, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nDate: Sat, 10 Oct 2026 21:44:20 GMT\r\nServer: Rtsp Server/3.0\r\n"+
		"Public: OPTIONS, DESCRIBE, ANNOUNCE, SETUP, PLAY, RECORD, PAUSE, TEARDOWN, SET_PARAMETER, GET_PARAMETER\r\n\r\n", string(options))

	_, err = client.Write(rtspDescribe)
	require.NoError(t, err)
	challenge := readRTSPReply(t, r)
	require.Contains(t, string(challenge), "RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n")
	require.Contains(t, string(challenge), `WWW-Authenticate: Digest realm="Login to 7K02D8APAZ1C3F9", nonce="00112233445566778899aabbccddeeff"`)

	_, err = client.Write(rtspDescribeBasic)
	require.NoError(t, err)
	retry := readRTSPReply(t, r)
	require.Contains(t, string(retry), "RTSP/1.0 401 Unauthorized\r\nCSeq: 3\r\n")

	require.NoError(t, client.Close())
	produced, err := waitRTSP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedRTSP{
		{Direction: "read", Command: "OPTIONS", Path: "/", CSeq: "1", Payload: rtspRead1},
		{Direction: "write", Status: "200", CSeq: "1", Payload: options},
		{Direction: "read", Command: "DESCRIBE", Path: "/Streaming/Channels/101", CSeq: "2", UserAgent: "LibVLC/3.0.18 (LIVE555 Streaming Media v2016.11.28)", Payload: rtspDescribe},
		{Direction: "write", Status: "401", CSeq: "2", Payload: challenge},
		{Direction: "read", Command: "DESCRIBE", Path: "/Streaming/Channels/101", CSeq: "3", AuthScheme: "basic", Username: "admin", Payload: rtspDescribeBasic},
		{Direction: "write", Status: "401", CSeq: "3", Payload: retry},
	}, produced.decoded)
}

func TestHandleRTSPCredentialsNotInDecoded(t *testing.T) {
	client, r, hp, done := startRTSP(t)
	digest := []byte("DESCRIBE rtsp://1.2.3.4/cam/realmonitor RTSP/1.0\r\nCSeq: 4\r\n" +
		`Authorization: Digest username="admin", realm="Login to 7K02D8APAZ1C3F9", nonce="00112233445566778899aabbccddeeff", uri="rtsp://1.2.3.4/cam/realmonitor", response="6629fae49393a05397450978507c4ef1"` + "\r\n\r\n")
	inURI := []byte("DESCRIBE rtsp://root:pass@1.2.3.4/live RTSP/1.0\r\nCSeq: 5\r\n\r\n")
	for _, req := range [][]byte{rtspDescribeBasic, digest, inURI} {
		_, err := client.Write(req)
		require.NoError(t, err)
		readRTSPReply(t, r)
	}
	require.NoError(t, client.Close())

	produced, err := waitRTSP(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedRTSP)
	require.Len(t, frames, 6)
	require.Equal(t, "admin", frames[0].Username)
	require.Equal(t, "digest", frames[2].AuthScheme)
	require.Equal(t, "admin", frames[2].Username)
	require.Equal(t, "6629fae49393a05397450978507c4ef1", frames[2].DigestResponse)
	require.Equal(t, parsedRTSP{Direction: "read", Command: "DESCRIBE", Path: "/live", CSeq: "5", AuthScheme: "uri", Username: "root", Payload: inURI}, frames[4])
	// passwords (12345 in Basic, pass in the URI) stay in the raw payload only
	for _, f := range frames {
		fields := strings.Join([]string{f.Command, f.Path, f.CSeq, f.UserAgent, f.AuthScheme, f.Username, f.DigestResponse}, " ")
		require.NotContains(t, fields, "12345")
		require.NotContains(t, fields, "pass")
	}
}

func TestHandleRTSPEarlyDisconnectStillProduces(t *testing.T) {
	client, _, hp, done := startRTSP(t)
	require.NoError(t, client.Close())

	produced, err := waitRTSP(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, produced.decoded)
	require.Equal(t, connection.EndClientClose, produced.endReason)
}

func TestHandleRTSPPartialRequestStored(t *testing.T) {
	client, _, hp, done := startRTSP(t)
	partial := rtspRead1[:48] // no blank line yet
	_, err := client.Write(partial)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	produced, err := waitRTSP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedRTSP{{Direction: "read", Command: "OPTIONS", Path: "/", CSeq: "1", Payload: partial}}, produced.decoded)
}

func TestHandleRTSPMalformedAfterRequest(t *testing.T) {
	client, r, hp, done := startRTSP(t)
	_, err := client.Write(rtspRead1)
	require.NoError(t, err)
	readRTSPReply(t, r)
	_, err = client.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	require.NoError(t, err)

	produced, err := waitRTSP(t, hp, done)
	require.ErrorIs(t, err, rtsp.ErrMalformed)
	require.Equal(t, connection.EndReadError, produced.endReason)
	frames := produced.decoded.([]parsedRTSP)
	require.Len(t, frames, 3)
	require.Equal(t, parsedRTSP{Direction: "read", Payload: []byte("GET / HTTP/1.1\r\n")}, frames[2])
}

func TestHandleRTSPMissingCSeq(t *testing.T) {
	client, r, hp, done := startRTSP(t)
	_, err := client.Write([]byte("OPTIONS * RTSP/1.0\r\n\r\n"))
	require.NoError(t, err)
	reply := readRTSPReply(t, r)
	require.True(t, strings.HasPrefix(string(reply), "RTSP/1.0 400 Bad Request\r\nDate: "))
	require.NoError(t, client.Close())

	produced, err := waitRTSP(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedRTSP)
	require.Equal(t, parsedRTSP{Direction: "write", Status: "400", Payload: reply}, frames[1])
}

func TestHandleRTSPOversizeBodyTruncated(t *testing.T) {
	client, r, hp, done := startRTSP(t)
	body := strings.Repeat("A", rtspMaxBody+100)
	req := "ANNOUNCE rtsp://1.2.3.4/live RTSP/1.0\r\nCSeq: 9\r\nContent-Type: application/sdp\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	go func() { _, _ = client.Write([]byte(req)) }()
	reply := readRTSPReply(t, r)
	require.Contains(t, string(reply), "RTSP/1.0 401 Unauthorized\r\nCSeq: 9\r\n")
	require.NoError(t, client.Close())

	produced, err := waitRTSP(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedRTSP)
	require.Len(t, frames, 2)
	require.True(t, frames[0].Truncated)
	require.Equal(t, "ANNOUNCE", frames[0].Command)
	require.Less(t, len(frames[0].Payload), rtspMaxBody+256)
}

func TestHandleRTSPBodyTooLarge(t *testing.T) {
	client, _, hp, done := startRTSP(t)
	_, err := client.Write([]byte("ANNOUNCE rtsp://1.2.3.4/live RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 99999999\r\n\r\n"))
	require.NoError(t, err)

	produced, err := waitRTSP(t, hp, done)
	require.ErrorIs(t, err, rtsp.ErrBodyTooLarge)
	frames := produced.decoded.([]parsedRTSP)
	require.Len(t, frames, 1)
	require.True(t, frames[0].Truncated)
}
