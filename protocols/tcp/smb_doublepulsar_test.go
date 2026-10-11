package tcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/recall"
	"github.com/mushorg/glutton/protocols/tcp/smb"
	"github.com/stretchr/testify/require"
)

// stubSMBRecall gives the test a fresh visit store and returns a function that
// advances its clock.
func stubSMBRecall(t *testing.T) func(time.Duration) {
	t.Helper()
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	orig := smbRecall
	smbRecall = recall.NewWithClock(recall.Config{Enabled: true, Gap: time.Hour}, func() time.Time { return now })
	t.Cleanup(func() { smbRecall = orig })
	return func(d time.Duration) { now = now.Add(d) }
}

func startSMBFrom(t *testing.T, remote net.Addr) (net.Conn, *fakeHoneypot, chan error) {
	t.Helper()
	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	serverConn = connWithRemote{Conn: serverConn, remote: remote}
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleSMB(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	return client, hp, done
}

// dpRequest builds a TRANS2 SESSION_SETUP request carrying opcode op in the
// Timeout field.
func dpRequest(t *testing.T, mid uint16, timeout uint32, data []byte) []byte {
	t.Helper()
	body := smbTrans2SessionSetupBody(data)
	binary.LittleEndian.PutUint32(body[13:17], timeout)
	return append(smbHeaderBytes(t, smbReqHeader(smb.CmdTransaction2, 1, 1, mid)), body...)
}

const (
	dpTimeoutPing = 0x23
	dpTimeoutExec = 0x61056200
	dpTimeoutKill = 0x77
)

func replyMID(pdu []byte) uint16    { return binary.LittleEndian.Uint16(pdu[30:32]) }
func replyNTStatus(p []byte) uint32 { return binary.LittleEndian.Uint32(p[5:9]) }

// reachVisit makes n-1 empty visits from remote so the next connection is
// visit n.
func reachVisit(t *testing.T, advance func(time.Duration), remote net.Addr, n int) {
	t.Helper()
	for i := 1; i < n; i++ {
		client, hp, done := startSMBFrom(t, remote)
		finishHandleSMB(t, client, done, hp)
		advance(time.Hour)
	}
}

func TestHandleSMBDoublePulsarCleanVisitRejectsPing(t *testing.T) {
	stubSMBRecall(t)
	client, hp, done := startSMBFrom(t, staticAddr{"203.0.113.9:4444"})
	writeSMBFrame(t, client, dpRequest(t, 0x41, dpTimeoutPing, nil))
	resp := readSMBFrame(t, client)
	require.Equal(t, uint16(0x41), replyMID(resp))
	require.Equal(t, uint32(0xc0000002), replyNTStatus(resp))

	frames := finishHandleSMB(t, client, done, hp).decoded.([]parsedSMB)
	for _, f := range frames {
		require.Empty(t, f.Variant)
		require.Zero(t, f.Visit)
	}
}

func TestHandleSMBDoublePulsarInfectedVisit(t *testing.T) {
	advance := stubSMBRecall(t)
	var stored [][]byte
	origStore, origRand := smbStore, smbReadRand
	smbStore = func(data []byte, folder string) (string, error) {
		stored = append(stored, append([]byte(nil), data...))
		return helpers.SHA256Hex(data), nil
	}
	sig := [8]byte{0x6f, 0x0a, 0x2d, 0x8d, 0x01, 0, 0, 0} // 0x018d2d0a6f
	smbReadRand = func(b []byte) (int, error) { return copy(b, sig[:]), nil }
	t.Cleanup(func() { smbStore, smbReadRand = origStore, origRand })

	remote := staticAddr{"203.0.113.9:4444"}
	reachVisit(t, advance, remote, 3)
	client, hp, done := startSMBFrom(t, remote)

	// Ping: infected reply with MID+0x10 and our signature.
	writeSMBFrame(t, client, dpRequest(t, 0x41, dpTimeoutPing, nil))
	resp := readSMBFrame(t, client)
	require.Equal(t, uint16(0x51), replyMID(resp))
	require.Zero(t, replyNTStatus(resp))
	require.Equal(t, sig[:], resp[14:22])

	// Exec: the payload is obfuscated with the key derived from that signature,
	// which is outside the 16-bit brute-force space.
	key := smb.DoublePulsarXORKey64(0x018d2d0a6f)
	require.Equal(t, uint32(0x75503953), key)
	cipher := smb.XORApply(dpTestPayload, key)
	writeSMBFrame(t, client, dpRequest(t, 0x42, dpTimeoutExec, cipher))
	resp = readSMBFrame(t, client)
	require.Equal(t, uint16(0x52), replyMID(resp))
	require.Zero(t, replyNTStatus(resp))

	// Kill.
	writeSMBFrame(t, client, dpRequest(t, 0x43, dpTimeoutKill, nil))
	resp = readSMBFrame(t, client)
	require.Equal(t, uint16(0x53), replyMID(resp))
	require.Zero(t, replyNTStatus(resp))

	frames := finishHandleSMB(t, client, done, hp).decoded.([]parsedSMB)

	var execRead *parsedSMB
	writes := 0
	for i := range frames {
		f := &frames[i]
		if f.Direction == "read" && f.Header.Command == smb.CmdTransaction2 && f.PayloadHash != "" {
			execRead = f
		}
		if f.Direction == "write" && f.Command != "" {
			if f.Variant != "" {
				writes++
				require.Equal(t, "infected", f.Variant)
				require.Equal(t, 3, f.Visit)
			}
		}
	}
	require.Equal(t, 3, writes, "ping, exec and kill replies are stamped")
	require.NotNil(t, execRead)
	require.Equal(t, fmt.Sprintf("%08x", key), execRead.XORKey)
	require.Equal(t, helpers.SHA256Hex(dpTestPayload), execRead.DecodedHash)
	require.Contains(t, stored, dpTestPayload)
}

func TestHandleSMBDoublePulsarInfectedFragmentedExec(t *testing.T) {
	advance := stubSMBRecall(t)
	origStore, origRand := smbStore, smbReadRand
	smbStore = func(data []byte, folder string) (string, error) { return helpers.SHA256Hex(data), nil }
	sig := [8]byte{0x6f, 0x0a, 0x2d, 0x8d, 0x01, 0, 0, 0}
	smbReadRand = func(b []byte) (int, error) { return copy(b, sig[:]), nil }
	t.Cleanup(func() { smbStore, smbReadRand = origStore, origRand })

	remote := staticAddr{"203.0.113.9:4444"}
	reachVisit(t, advance, remote, 3)
	client, hp, done := startSMBFrom(t, remote)

	writeSMBFrame(t, client, dpRequest(t, 0x41, dpTimeoutPing, nil))
	readSMBFrame(t, client)

	key := smb.DoublePulsarXORKey64(0x018d2d0a6f)
	cipher := smb.XORApply(dpTestPayload, key)
	split := 16
	first := cipher[:split]
	const dataStart = 33
	body := make([]byte, dataStart+len(first))
	body[0] = 15
	binary.LittleEndian.PutUint32(body[13:17], dpTimeoutExec)
	binary.LittleEndian.PutUint16(body[3:5], uint16(len(cipher)))
	binary.LittleEndian.PutUint16(body[23:25], uint16(len(first)))
	binary.LittleEndian.PutUint16(body[25:27], uint16(32+dataStart))
	body[27] = 1
	binary.LittleEndian.PutUint16(body[29:31], uint16(smb.Trans2SessionSetup))
	copy(body[dataStart:], first)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdTransaction2, 1, 1, 0x42)), body...))
	resp := readSMBFrame(t, client)
	require.Equal(t, uint16(0x42), replyMID(resp), "interim reply is not the implant ack")

	rest := cipher[split:]
	secBody := smbTrans2SecondaryBody(uint16(split), uint16(len(rest)))
	binary.LittleEndian.PutUint16(secBody[13:15], 32+uint16(len(secBody)))
	secBody = append(secBody, rest...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdTransaction2Secondary, 1, 1, 0x43)), secBody...))
	resp = readSMBFrame(t, client)
	require.Equal(t, uint16(0x53), replyMID(resp))
	require.Zero(t, replyNTStatus(resp))

	frames := finishHandleSMB(t, client, done, hp).decoded.([]parsedSMB)
	var found bool
	for _, f := range frames {
		if f.Direction == "read" && f.DecodedHash != "" {
			found = true
			require.Equal(t, fmt.Sprintf("%08x", key), f.XORKey)
			require.Equal(t, helpers.SHA256Hex(dpTestPayload), f.DecodedHash)
		}
	}
	require.True(t, found)
}
