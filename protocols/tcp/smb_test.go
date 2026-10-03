package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/smb"
	"github.com/stretchr/testify/require"
)

func smbReqHeader(cmd byte, tid, uid, mid uint16) smb.SMBHeader {
	h := smb.SMBHeader{
		Protocol: [4]byte{0xff, 'S', 'M', 'B'},
		Command:  cmd,
		Flags:    0x18,
		Flags2:   [2]byte{0x53, 0xc8}, // Unicode | NT status | EXTENDED_SECURITY
	}
	binary.LittleEndian.PutUint16(h.PIDLow[:], 0xfeff)
	binary.LittleEndian.PutUint16(h.TID[:], tid)
	binary.LittleEndian.PutUint16(h.UID[:], uid)
	binary.LittleEndian.PutUint16(h.MID[:], mid)
	return h
}

func smbHeaderBytes(t *testing.T, h smb.SMBHeader) []byte {
	t.Helper()
	b := make([]byte, 32)
	copy(b[0:4], h.Protocol[:])
	b[4] = h.Command
	copy(b[5:9], h.Status[:])
	b[9] = h.Flags
	copy(b[10:12], h.Flags2[:])
	copy(b[12:14], h.PIDHigh[:])
	copy(b[14:22], h.SecurityFeatures[:])
	copy(b[22:24], h.Reserved[:])
	copy(b[24:26], h.TID[:])
	copy(b[26:28], h.PIDLow[:])
	copy(b[28:30], h.UID[:])
	copy(b[30:32], h.MID[:])
	return b
}

func readSMBFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	require.NoError(t, r.(net.Conn).SetReadDeadline(time.Now().Add(2*time.Second)))
	var nb [4]byte
	_, err := io.ReadFull(r, nb[:])
	require.NoError(t, err)
	n := int(nb[1])<<16 | int(nb[2])<<8 | int(nb[3])
	require.Greater(t, n, 0)
	pdu := make([]byte, n)
	_, err = io.ReadFull(r, pdu)
	require.NoError(t, err)
	return pdu
}

func writeSMBFrame(t *testing.T, w io.Writer, pdu []byte) {
	t.Helper()
	require.NoError(t, w.(net.Conn).SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err := w.Write(smb.WrapSessionMessage(pdu))
	require.NoError(t, err)
}

func TestHandleSMBMS17010Path(t *testing.T) {
	client, serverConn := net.Pipe()
	defer client.Close()

	hp := newFakeHoneypot()
	logger := &recordingLogger{}

	done := make(chan error, 1)
	go func() {
		done <- HandleSMB(context.Background(), serverConn, connection.Metadata{}, logger, hp)
	}()

	// 1) Negotiate
	negBody := []byte{0x00, 0x0c, 0x00} // WordCount=0, ByteCount=12
	negBody = append(negBody, []byte("\x02NT LM 0.12\x00")...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x72, 0, 0, 1)), negBody...))
	negResp := readSMBFrame(t, client)
	require.Equal(t, byte(0x72), negResp[4])
	require.Equal(t, [4]byte{}, [4]byte(negResp[5:9]))
	negFlags2 := binary.LittleEndian.Uint16(negResp[10:12])
	require.Equal(t, uint16(0), negFlags2&0x0800, "EXTENDED_SECURITY must be cleared")
	require.NotEqual(t, uint16(0), negFlags2&0x8000, "Unicode must be set")

	// 2) Session Setup AndX (basic; body ignored by handler)
	ssBody := []byte{
		0x0d,       // WordCount
		0xff, 0x00, // AndX none
		0x00, 0x00, // AndXOffset
		0xff, 0xff, // MaxBuffer
		0x02, 0x00, // MaxMpx
		0x01, 0x00, // VcNumber
		0x00, 0x00, 0x00, 0x00, // SessionKey
		0x00, 0x00, // OEMPasswordLen
		0x00, 0x00, // UnicodePasswordLen
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, // ByteCount
	}
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x73, 0, 0, 2)), ssBody...))
	ssResp := readSMBFrame(t, client)
	require.Equal(t, byte(0x73), ssResp[4])
	require.Equal(t, [4]byte{}, [4]byte(ssResp[5:9]))
	uid := binary.LittleEndian.Uint16(ssResp[28:30])
	require.NotZero(t, uid)

	// 3) Tree Connect AndX to IPC$
	// Fixed prefix: WordCount(1)+AndX(4)+Flags(2)+PasswordLength(2)+ByteCount(2) = 11.
	// PasswordLength=1 → one password byte; then optional pad so path is 2-byte aligned
	// relative to the SMB header (offset 32+11+1 = 44, already even — no pad).
	path := encodeSMBPath(`\\127.0.0.1\IPC$`)
	service := []byte("?????\x00")
	dataBytes := append([]byte{0x00}, path...) // empty password byte + path
	dataBytes = append(dataBytes, service...)
	tcBody := []byte{
		0x04,       // WordCount
		0xff, 0x00, // AndX none
		0x00, 0x00, // AndXOffset
		0x00, 0x00, // Flags
		0x01, 0x00, // PasswordLength
		0x00, 0x00, // ByteCount placeholder
	}
	binary.LittleEndian.PutUint16(tcBody[9:11], uint16(len(dataBytes)))
	tcBody = append(tcBody, dataBytes...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x75, 0, uid, 3)), tcBody...))
	tcResp := readSMBFrame(t, client)
	require.Equal(t, byte(0x75), tcResp[4])
	require.Equal(t, [4]byte{}, [4]byte(tcResp[5:9]))
	tid := binary.LittleEndian.Uint16(tcResp[24:26])
	require.NotZero(t, tid)
	require.Contains(t, string(tcResp[32:]), "IPC\x00")

	// 4) SMB_COM_TRANSACTION — MS17-010 PeekNamedPipe fingerprint
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x25, tid, uid, 4)), 0x00, 0x00, 0x00))
	txResp := readSMBFrame(t, client)
	require.Equal(t, byte(0x25), txResp[4])
	status := binary.LittleEndian.Uint32(txResp[5:9])
	require.Equal(t, uint32(0xc0000205), status, "STATUS_INSUFF_SERVER_RESOURCES")

	// 5) Cleanup commands must get success replies (scanners hang otherwise).
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x71, tid, uid, 5)), 0x00, 0x00, 0x00))
	tdResp := readSMBFrame(t, client)
	require.Equal(t, byte(0x71), tdResp[4])
	require.Equal(t, [4]byte{}, [4]byte(tdResp[5:9]))

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x74, 0, uid, 6)), 0x02, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00))
	loResp := readSMBFrame(t, client)
	require.Equal(t, byte(0x74), loResp[4])
	require.Equal(t, [4]byte{}, [4]byte(loResp[5:9]))

	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSMB did not finish")
	}

	ev := waitProduced(t, hp)
	require.Equal(t, "smb", ev.protocol)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(frames), 8) // 4 request/response pairs minimum before cleanup
	var sawTx bool
	for _, f := range frames {
		if f.Direction == "write" && f.Header.Command == 0x25 {
			require.Equal(t, [4]byte{0x05, 0x02, 0x00, 0xc0}, f.Header.Status)
			sawTx = true
		}
	}
	require.True(t, sawTx, "expected TRANSACTION write frame with MS17-010 status")
}

func encodeSMBPath(path string) []byte {
	// UTF-16LE with trailing NUL.
	out := make([]byte, 0, len(path)*2+2)
	for _, r := range path {
		out = append(out, byte(r), 0)
	}
	return append(out, 0, 0)
}

func startHandleSMB(t *testing.T) (client net.Conn, hp *fakeHoneypot, done chan error) {
	t.Helper()
	var serverConn net.Conn
	client, serverConn = net.Pipe()
	hp = newFakeHoneypot()
	done = make(chan error, 1)
	go func() {
		done <- HandleSMB(context.Background(), serverConn, connection.Metadata{}, &recordingLogger{}, hp)
	}()
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client, hp, done
}

func finishHandleSMB(t *testing.T, client net.Conn, done <-chan error, hp *fakeHoneypot) producedTCP {
	t.Helper()
	require.NoError(t, client.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("HandleSMB did not finish")
	}
	ev := waitProduced(t, hp)
	require.Equal(t, "smb", ev.protocol)
	return ev
}

func TestHandleSMBReassemblesSplitFrame(t *testing.T) {
	client, hp, done := startHandleSMB(t)

	negBody := []byte{0x00, 0x0c, 0x00}
	negBody = append(negBody, []byte("\x02NT LM 0.12\x00")...)
	pdu := append(smbHeaderBytes(t, smbReqHeader(0x72, 0, 0, 1)), negBody...)
	framed := smb.WrapSessionMessage(pdu)
	require.NoError(t, client.SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err := client.Write(framed[:2])
	require.NoError(t, err)
	_, err = client.Write(framed[2:])
	require.NoError(t, err)

	negResp := readSMBFrame(t, client)
	require.Equal(t, byte(0x72), negResp[4])

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(frames), 2)
	require.Equal(t, "SMB_COM_NEGOTIATE", frames[0].Command)
}

func TestHandleSMBCapturesLargeNtTransact(t *testing.T) {
	client, hp, done := startHandleSMB(t)

	const body = 8192
	pdu := make([]byte, body)
	copy(pdu, smbHeaderBytes(t, smbReqHeader(smb.CmdNtTransact, 1, 1, 1)))
	writeSMBFrame(t, client, pdu)
	resp := readSMBFrame(t, client)
	require.Equal(t, byte(smb.CmdNtTransact), resp[4])
	require.Equal(t, [4]byte{}, [4]byte(resp[5:9]), "NT Transact stub must be success, not MS17-010 fingerprint")
	require.Equal(t, byte(18), resp[32])

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)
	var sawRead, sawWrite bool
	for _, f := range frames {
		if f.Direction == "read" && f.Header.Command == smb.CmdNtTransact {
			require.Equal(t, "SMB_COM_NT_TRANSACT", f.Command)
			require.False(t, f.Truncated)
			require.Equal(t, 4+body, len(f.Payload))
			sawRead = true
		}
		if f.Direction == "write" && f.Header.Command == smb.CmdNtTransact {
			sawWrite = true
		}
	}
	require.True(t, sawRead, "expected stored NT_TRANSACT read larger than 1024")
	require.True(t, sawWrite, "expected NT_TRANSACT stub write")
}

func TestHandleSMBTruncatesOversizedMessage(t *testing.T) {
	client, hp, done := startHandleSMB(t)

	n := maxSMBMessage + 64
	pdu := make([]byte, n)
	copy(pdu, smbHeaderBytes(t, smbReqHeader(smb.CmdNtTransact, 1, 1, 1)))
	writeSMBFrame(t, client, pdu)
	_ = readSMBFrame(t, client)

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)
	var sawTrunc bool
	for _, f := range frames {
		if f.Direction == "read" && f.Header.Command == smb.CmdNtTransact {
			require.True(t, f.Truncated)
			require.Equal(t, 4+maxSMBMessage, len(f.Payload))
			sawTrunc = true
		}
	}
	require.True(t, sawTrunc, "expected truncated NT_TRANSACT read")
}

func TestHandleSMBStoresSMB2WithoutAbort(t *testing.T) {
	client, hp, done := startHandleSMB(t)

	pdu := make([]byte, 64)
	pdu[0] = 0xfe
	copy(pdu[1:4], []byte("SMB"))
	binary.LittleEndian.PutUint16(pdu[4:6], 64)
	writeSMBFrame(t, client, pdu)
	resp := readSMBFrame(t, client)
	require.Equal(t, byte(0xfe), resp[0])
	require.Equal(t, "SMB", string(resp[1:4]))
	flags := binary.LittleEndian.Uint32(resp[16:20])
	require.Equal(t, uint32(0x1), flags&0x1, "SMB2_FLAGS_SERVER_TO_REDIR")

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)
	require.GreaterOrEqual(t, len(frames), 2)
	require.Equal(t, "SMB2_NEGOTIATE", frames[0].Command)
	require.Equal(t, "read", frames[0].Direction)
	require.Equal(t, "SMB2_NEGOTIATE", frames[1].Command)
	require.Equal(t, "write", frames[1].Direction)
}
