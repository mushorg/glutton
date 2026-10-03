package tcp

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

// 43-byte Connection Request with Cookie: mstshash=hello and RDP_NEG_REQ TLS|CredSSP
var rdpCRHello = mustDecodeHex("0300002b26e00000000000436f6f6b69653a206d737473686173683d68656c6c6f0d0a0100080003000000")

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHandleRDPNegotiationAndTLSStub(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, logger, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))

	_, err := client.Write(rdpCRHello)
	require.NoError(t, err)

	cc := make([]byte, 19)
	_, err = io.ReadFull(client, cc)
	require.NoError(t, err)
	require.Equal(t, byte(0x03), cc[0])
	require.Equal(t, byte(0xd0), cc[5])

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         "rdp",
	})
	require.NoError(t, tlsClient.Handshake())
	_ = tlsClient.Close()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "rdp", produced.protocol)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}

	events, ok := produced.decoded.([]parsedRDP)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(events), 4)

	require.Equal(t, "read", events[0].Direction)
	require.Equal(t, rdpCRHello, events[0].Payload, "first payload must stay the CR (no buffer reuse)")
	require.Equal(t, byte(3), events[0].Header.Version)

	require.Equal(t, "write", events[1].Direction)
	require.Equal(t, cc, events[1].Payload)

	require.Equal(t, "read", events[2].Direction)
	require.Equal(t, byte(0x16), events[2].Payload[0], "ClientHello")
	require.Equal(t, byte(0), events[2].Header.Version, "TLS frames have no TPKT header")

	require.Equal(t, "write", events[3].Direction)
	require.Equal(t, byte(0x16), events[3].Payload[0], "TLS stub ServerHello flight")
	require.NotEqual(t, events[1].Payload, events[3].Payload, "must not re-send Connection Confirm")
}

func TestHandleRDPPayloadNotOverwritten(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()

	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := client.Write(rdpCRHello)
	require.NoError(t, err)

	cc := make([]byte, 19)
	_, err = io.ReadFull(client, cc)
	require.NoError(t, err)

	// Second read overwrites the shared buffer; copied payloads must stay intact.
	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		ServerName:         "rdp",
	})
	_ = tlsClient.Handshake()
	_ = client.Close()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	events := produced.decoded.([]parsedRDP)
	require.Equal(t, rdpCRHello, events[0].Payload)
}

func TestHandleRDPEarlyDisconnect(t *testing.T) {
	client, serverConn := net.Pipe()

	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleRDP(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()

	require.NoError(t, client.Close())

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}

	produced := waitProduced(t, hp)
	require.Equal(t, "rdp", produced.protocol)
	events, ok := produced.decoded.([]parsedRDP)
	require.True(t, ok)
	require.Empty(t, events)
}
