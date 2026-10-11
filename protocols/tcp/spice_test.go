package tcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/spice"
	"github.com/stretchr/testify/require"
)

// SPICE link message with no caps for the main channel, sent to tcp/5907 in
// Ochi event a1089002-b561-402e-8143-7cfe51e439ac.
var spiceScannerProbe = []byte("REDQ\x02\x00\x00\x00\x02\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00")

var spiceScannerRead = parsedSPICE{
	Direction: "read", Command: "LinkMess", Version: "2.2", ChannelType: "main", Payload: spiceScannerProbe,
}

// spiceTestKey is generated once for the test binary; the handler's
// spiceKey is swapped to return it.
var spiceTestKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, spice.KeyBits)
	if err != nil {
		panic(err)
	}
	return k
})

// spiceLinkMess builds a synthetic link message with common caps, as
// spice-gtk sends it (auth selection, SPICE auth, mini header).
func spiceLinkMess(channel uint8, common []uint32) []byte {
	body := binary.LittleEndian.AppendUint32(nil, 0)
	body = append(body, channel, 0)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(common)))
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = binary.LittleEndian.AppendUint32(body, spice.LinkMessLen)
	for _, c := range common {
		body = binary.LittleEndian.AppendUint32(body, c)
	}
	b := append([]byte("REDQ"), 2, 0, 0, 0, 2, 0, 0, 0)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(body)))
	return append(b, body...)
}

func startSPICE(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	prev := spiceKey
	spiceKey = func() (*rsa.PrivateKey, error) { return spiceTestKey(), nil }
	t.Cleanup(func() { spiceKey = prev })

	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	serverConn = connWithRemote{Conn: serverConn, remote: staticAddr{addr: "192.0.2.1:61000"}}
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleSPICE(context.Background(), serverConn, connection.Metadata{TargetPort: 5907}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	return client, hp, done
}

// finishSPICE closes the client, waits for the handler and returns the
// single produced event.
func finishSPICE(t *testing.T, client net.Conn, hp *fakeHoneypot, done chan error) (producedTCP, []parsedSPICE) {
	t.Helper()
	require.NoError(t, client.Close())
	waitHandlerDone(t, done)
	produced := waitProduced(t, hp)
	require.Equal(t, "spice", produced.protocol)
	require.Empty(t, hp.produced, "exactly one event per session")
	events, ok := produced.decoded.([]parsedSPICE)
	require.True(t, ok)
	return produced, events
}

func writeSPICE(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	_, err := conn.Write(b)
	require.NoError(t, err)
}

func readSPICE(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := io.ReadFull(conn, b)
	require.NoError(t, err)
	return b
}

// readLinkReply reads and checks a whole SpiceLinkHeader + SpiceLinkReply.
func readLinkReply(t *testing.T, conn net.Conn) ([]byte, spice.LinkReply) {
	t.Helper()
	head := readSPICE(t, conn, spice.HeaderLen)
	b := append(head, readSPICE(t, conn, int(binary.LittleEndian.Uint32(head[12:])))...)
	r, err := spice.ParseLinkReply(b)
	require.NoError(t, err)
	return b, r
}

func spiceTicket(t *testing.T, pubDER []byte, password string) []byte {
	t.Helper()
	pub, err := spice.MarshalPublicKey(&spiceTestKey().PublicKey)
	require.NoError(t, err)
	require.Equal(t, pub, pubDER, "the reply carries the server key")
	ct, err := spice.EncryptTicket(&spiceTestKey().PublicKey, password, rand.Reader)
	require.NoError(t, err)
	return ct
}

func TestHandleSPICEScannerProbe(t *testing.T) {
	client, hp, done := startSPICE(t)

	writeSPICE(t, client, spiceScannerProbe)
	reply, r := readLinkReply(t, client)
	require.Equal(t, spice.Header{Major: 2, Minor: 2, Size: 186}, r.Header)
	require.Equal(t, uint32(spice.LinkErrOK), r.Error)
	require.Equal(t, uint32(178), r.CapsOffset)
	require.Equal(t, []uint32{0x0b}, r.CommonCaps)
	require.Equal(t, []uint32{0x0f}, r.ChannelCaps)
	pub, err := spice.MarshalPublicKey(&spiceTestKey().PublicKey)
	require.NoError(t, err)
	require.Equal(t, pub, r.PubKey)

	produced, events := finishSPICE(t, client, hp, done)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, spiceScannerProbe, produced.payload)
	require.Equal(t, []parsedSPICE{
		spiceScannerRead,
		{Direction: "write", Command: "LinkReply", Status: "OK", CommonCaps: "0000000b", ChannelCaps: "0000000f", Payload: reply},
	}, events)
}

func TestHandleSPICETicketRecordsPassword(t *testing.T) {
	client, hp, done := startSPICE(t)

	// the scanner sets no caps, so the ticket follows the reply directly
	writeSPICE(t, client, spiceScannerProbe)
	reply, r := readLinkReply(t, client)
	ticket := spiceTicket(t, r.PubKey, "hunter2")
	writeSPICE(t, client, ticket)
	require.Equal(t, []byte{7, 0, 0, 0}, readSPICE(t, client, 4))
	_, err := client.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF, "the link is closed after the result")

	produced, events := finishSPICE(t, client, hp, done)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
	require.Equal(t, []parsedSPICE{
		spiceScannerRead,
		{Direction: "write", Command: "LinkReply", Status: "OK", CommonCaps: "0000000b", ChannelCaps: "0000000f", Payload: reply},
		{Direction: "read", Command: "Ticket", Password: "hunter2", Payload: ticket},
		{Direction: "write", Command: "LinkResult", Status: "PermissionDenied", Payload: []byte{7, 0, 0, 0}},
	}, events)
}

func TestHandleSPICEAuthSelection(t *testing.T) {
	client, hp, done := startSPICE(t)

	// a display channel from a client with auth selection; no main caps
	mess := spiceLinkMess(2, []uint32{0x0b})
	writeSPICE(t, client, mess)
	reply, r := readLinkReply(t, client)
	require.Empty(t, r.ChannelCaps)
	mech := []byte{1, 0, 0, 0}
	writeSPICE(t, client, mech)
	ticket := spiceTicket(t, r.PubKey, "")
	writeSPICE(t, client, ticket)
	require.Equal(t, []byte{7, 0, 0, 0}, readSPICE(t, client, 4))

	_, events := finishSPICE(t, client, hp, done)
	require.Equal(t, []parsedSPICE{
		{Direction: "read", Command: "LinkMess", Version: "2.2", ChannelType: "display", CommonCaps: "0000000b", Payload: mess},
		{Direction: "write", Command: "LinkReply", Status: "OK", CommonCaps: "0000000b", Payload: reply},
		{Direction: "read", Command: "AuthMechanism", AuthMechanism: "SPICE", Payload: mech},
		{Direction: "read", Command: "Ticket", Payload: ticket},
		{Direction: "write", Command: "LinkResult", Status: "PermissionDenied", Payload: []byte{7, 0, 0, 0}},
	}, events)
}

func TestHandleSPICERejectsSASL(t *testing.T) {
	client, hp, done := startSPICE(t)

	writeSPICE(t, client, spiceLinkMess(1, []uint32{0x0f}))
	readLinkReply(t, client)
	writeSPICE(t, client, []byte{2, 0, 0, 0})
	_, r := readLinkReply(t, client)
	require.Equal(t, uint32(spice.LinkErrInvalidData), r.Error)

	_, events := finishSPICE(t, client, hp, done)
	require.Len(t, events, 4)
	require.Equal(t, "SASL", events[2].AuthMechanism)
	require.Equal(t, parsedSPICE{Direction: "write", Command: "LinkReply", Status: "InvalidData", Payload: spice.BuildLinkError(spice.LinkErrInvalidData)}, events[3])
}

func TestHandleSPICEUndecryptableTicket(t *testing.T) {
	client, hp, done := startSPICE(t)

	writeSPICE(t, client, spiceScannerProbe)
	readLinkReply(t, client)
	ticket := make([]byte, spice.TicketLen)
	writeSPICE(t, client, ticket)
	require.Equal(t, []byte{7, 0, 0, 0}, readSPICE(t, client, 4))

	_, events := finishSPICE(t, client, hp, done)
	require.Equal(t, parsedSPICE{Direction: "read", Command: "Ticket", Payload: ticket}, events[2])
}

func TestHandleSPICEBadMagic(t *testing.T) {
	client, hp, done := startSPICE(t)

	probe := []byte("GET / HTTP/1.0\r\n\r\n")
	writeSPICE(t, client, probe)
	_, r := readLinkReply(t, client)
	require.Equal(t, uint32(spice.LinkErrInvalidMagic), r.Error)

	_, events := finishSPICE(t, client, hp, done)
	// the rest of the first segment is kept with the header
	require.Equal(t, []parsedSPICE{
		{Direction: "read", Payload: probe},
		{Direction: "write", Command: "LinkReply", Status: "InvalidMagic", Payload: spice.BuildLinkError(spice.LinkErrInvalidMagic)},
	}, events)
}

func TestHandleSPICEOversizeLinkMess(t *testing.T) {
	client, hp, done := startSPICE(t)

	head := append([]byte("REDQ"), 2, 0, 0, 0, 2, 0, 0, 0)
	head = binary.LittleEndian.AppendUint32(head, 1<<20)
	writeSPICE(t, client, head)
	_, r := readLinkReply(t, client)
	require.Equal(t, uint32(spice.LinkErrInvalidData), r.Error)

	_, events := finishSPICE(t, client, hp, done)
	require.Equal(t, []parsedSPICE{
		{Direction: "read", Command: "LinkMess", Version: "2.2", Payload: head},
		{Direction: "write", Command: "LinkReply", Status: "InvalidData", Payload: spice.BuildLinkError(spice.LinkErrInvalidData)},
	}, events)
}

func TestHandleSPICEVersionMismatch(t *testing.T) {
	client, hp, done := startSPICE(t)

	head := append([]byte("REDQ"), 1, 0, 0, 0, 0, 0, 0, 0)
	head = binary.LittleEndian.AppendUint32(head, 18)
	writeSPICE(t, client, head)
	_, r := readLinkReply(t, client)
	require.Equal(t, uint32(spice.LinkErrVersionMismatch), r.Error)

	_, events := finishSPICE(t, client, hp, done)
	require.Equal(t, "1.0", events[0].Version)
	require.Equal(t, "VersionMismatch", events[1].Status)
}

func TestHandleSPICEEarlyDisconnect(t *testing.T) {
	t.Run("mid header", func(t *testing.T) {
		client, hp, done := startSPICE(t)
		writeSPICE(t, client, spiceScannerProbe[:10])
		produced, events := finishSPICE(t, client, hp, done)
		require.Equal(t, connection.EndClientClose, produced.endReason)
		require.Equal(t, []parsedSPICE{{Direction: "read", Payload: spiceScannerProbe[:10]}}, events)
	})
	t.Run("mid body", func(t *testing.T) {
		client, hp, done := startSPICE(t)
		writeSPICE(t, client, spiceScannerProbe[:20])
		_, events := finishSPICE(t, client, hp, done)
		require.Equal(t, []parsedSPICE{{Direction: "read", Command: "LinkMess", Version: "2.2", Payload: spiceScannerProbe[:20]}}, events)
	})
	t.Run("mid ticket", func(t *testing.T) {
		client, hp, done := startSPICE(t)
		writeSPICE(t, client, spiceScannerProbe)
		readLinkReply(t, client)
		writeSPICE(t, client, []byte{1, 2, 3})
		_, events := finishSPICE(t, client, hp, done)
		require.Len(t, events, 3)
		require.Equal(t, parsedSPICE{Direction: "read", Command: "Ticket", Payload: []byte{1, 2, 3}}, events[2])
	})
	t.Run("silent", func(t *testing.T) {
		client, hp, done := startSPICE(t)
		_, events := finishSPICE(t, client, hp, done)
		require.Empty(t, events)
	})
}
