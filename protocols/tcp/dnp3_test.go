package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/dnp3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// dnp3Frame builds a master-to-outstation link frame with optional user data.
func dnp3Frame(control byte, dest, src uint16, user []byte) []byte {
	b := []byte{0x05, 0x64, byte(dnp3.MinLength + len(user)), control}
	b = binary.LittleEndian.AppendUint16(b, dest)
	b = binary.LittleEndian.AppendUint16(b, src)
	b = binary.LittleEndian.AppendUint16(b, dnp3.CRC(b))
	for len(user) > 0 {
		n := min(len(user), 16)
		b = append(b, user[:n]...)
		b = binary.LittleEndian.AppendUint16(b, dnp3.CRC(user[:n]))
		user = user[n:]
	}
	return b
}

func startDNP3(t *testing.T) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	viper.Set("dnp3.address", 10)
	t.Cleanup(func() { viper.Set("dnp3.address", nil) })
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleDNP3(context.Background(), serverConn, connection.Metadata{TargetPort: 20000}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	return client, hp, done
}

func waitDNP3Event(t *testing.T, hp *fakeHoneypot, done chan error) producedTCP {
	t.Helper()
	require.NoError(t, <-done)
	select {
	case ev := <-hp.produced:
		require.Equal(t, "dnp3", ev.protocol)
		require.Empty(t, hp.produced, "expected exactly one produced event")
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced DNP3 event")
		return producedTCP{}
	}
}

func readDNP3Reply(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	b := make([]byte, dnp3.HeaderSize)
	_, err := io.ReadFull(conn, b)
	require.NoError(t, err)
	return b
}

func TestHandleDNP3Sweep(t *testing.T) {
	client, hp, done := startDNP3(t)

	// Frames from the captured sweep: REQUEST_LINK_STATUS from 3 to 0..2, then
	// one aimed at the outstation and one that is not for it.
	var want []parsedDNP3
	for _, dest := range []uint16{0, 1, 2, 10, 11} {
		f := dnp3Frame(0xc9, dest, 3, nil)
		_, err := client.Write(f)
		require.NoError(t, err)
		want = append(want, parsedDNP3{Direction: "read", Command: "REQUEST_LINK_STATUS", Dest: dest, Src: 3, Payload: f})
		if dest == 10 {
			reply := readDNP3Reply(t, client)
			require.Equal(t, []byte{0x05, 0x64, 0x05, 0x0b, 0x03, 0x00, 0x0a, 0x00}, reply[:8])
			want = append(want, parsedDNP3{Direction: "write", Command: "LINK_STATUS", Dest: 3, Src: 10, Status: "LINK_STATUS", Payload: reply})
		}
	}
	require.NoError(t, client.Close())

	ev := waitDNP3Event(t, hp, done)
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, want, ev.decoded)
}

func TestHandleDNP3TestLinkAndUserData(t *testing.T) {
	client, hp, done := startDNP3(t)
	user := make([]byte, 20) // two data blocks

	testLink := dnp3Frame(0xc2, 10, 4, nil)
	_, err := client.Write(testLink)
	require.NoError(t, err)
	ackTL := readDNP3Reply(t, client)

	confirmed := dnp3Frame(0xc3, 10, 4, user)
	_, err = client.Write(confirmed)
	require.NoError(t, err)
	ackCUD := readDNP3Reply(t, client)

	// Corrupt the first block CRC: recorded as BAD_CRC, no reply, session continues.
	corrupt := dnp3Frame(0xc3, 10, 4, user)
	corrupt[dnp3.HeaderSize+16] ^= 0xff
	_, err = client.Write(corrupt)
	require.NoError(t, err)

	unconfirmed := dnp3Frame(0xc4, 10, 4, user[:3])
	_, err = client.Write(unconfirmed)
	require.NoError(t, err)
	require.NoError(t, client.Close())

	ev := waitDNP3Event(t, hp, done)
	require.Equal(t, []parsedDNP3{
		{Direction: "read", Command: "TEST_LINK_STATES", Dest: 10, Src: 4, Payload: testLink},
		{Direction: "write", Command: "ACK", Dest: 4, Src: 10, Status: "ACK", Payload: ackTL},
		{Direction: "read", Command: "CONFIRMED_USER_DATA", Dest: 10, Src: 4, Payload: confirmed},
		{Direction: "write", Command: "ACK", Dest: 4, Src: 10, Status: "ACK", Payload: ackCUD},
		{Direction: "read", Command: "BAD_CRC", Dest: 10, Src: 4, Payload: corrupt},
		{Direction: "read", Command: "UNCONFIRMED_USER_DATA", Dest: 10, Src: 4, Payload: unconfirmed},
	}, ev.decoded)
}

func TestHandleDNP3Malformed(t *testing.T) {
	t.Run("bad start bytes", func(t *testing.T) {
		client, hp, done := startDNP3(t)
		junk := []byte("GET / HTTP/1.1\r\n")
		go client.Write(junk)

		ev := waitDNP3Event(t, hp, done)
		require.Equal(t, connection.EndHandlerClose, ev.endReason)
		require.Equal(t, []parsedDNP3{{Direction: "read", Command: "UNKNOWN", Payload: junk[:dnp3.HeaderSize]}}, ev.decoded)
	})

	t.Run("bad header crc", func(t *testing.T) {
		client, hp, done := startDNP3(t)
		f := dnp3Frame(0xc9, 10, 3, nil)
		f[9] ^= 0xff
		go client.Write(f)

		ev := waitDNP3Event(t, hp, done)
		require.Equal(t, connection.EndHandlerClose, ev.endReason)
		require.Equal(t, []parsedDNP3{{Direction: "read", Command: "BAD_CRC", Payload: f}}, ev.decoded)
	})
}

func TestHandleDNP3EarlyDisconnect(t *testing.T) {
	t.Run("no bytes", func(t *testing.T) {
		client, hp, done := startDNP3(t)
		require.NoError(t, client.Close())

		ev := waitDNP3Event(t, hp, done)
		require.Equal(t, connection.EndClientClose, ev.endReason)
		require.Equal(t, []parsedDNP3{}, ev.decoded)
	})

	t.Run("partial header", func(t *testing.T) {
		client, hp, done := startDNP3(t)
		f := dnp3Frame(0xc9, 10, 3, nil)
		_, err := client.Write(f[:4])
		require.NoError(t, err)
		require.NoError(t, client.Close())

		ev := waitDNP3Event(t, hp, done)
		require.Equal(t, connection.EndClientClose, ev.endReason)
		require.Equal(t, []parsedDNP3{{Direction: "read", Command: "UNKNOWN", Payload: f[:4]}}, ev.decoded)
	})

	t.Run("partial data block", func(t *testing.T) {
		client, hp, done := startDNP3(t)
		f := dnp3Frame(0xc3, 10, 3, make([]byte, 8))
		_, err := client.Write(f[:dnp3.HeaderSize+4])
		require.NoError(t, err)
		require.NoError(t, client.Close())

		ev := waitDNP3Event(t, hp, done)
		events, ok := ev.decoded.([]parsedDNP3)
		require.True(t, ok)
		require.Len(t, events, 1)
		require.Equal(t, f[:dnp3.HeaderSize+4], events[0].Payload)
		require.Equal(t, "CONFIRMED_USER_DATA", events[0].Command)
	})
}

func TestHandleDNP3FrameCap(t *testing.T) {
	client, hp, done := startDNP3(t)
	go func() {
		for i := 0; i < maxDNP3Frames+10; i++ {
			if _, err := client.Write(dnp3Frame(0xc9, uint16(100+i), 3, nil)); err != nil {
				return
			}
		}
	}()

	ev := waitDNP3Event(t, hp, done)
	require.Equal(t, connection.EndMaxFrames, ev.endReason)
	events, ok := ev.decoded.([]parsedDNP3)
	require.True(t, ok)
	require.Len(t, events, maxDNP3Frames)
	require.True(t, events[len(events)-1].Truncated)
	require.False(t, events[len(events)-2].Truncated)
}
