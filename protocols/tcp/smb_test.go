package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
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
	require.NotEqual(t, uint16(0), negFlags2&0x0800, "EXTENDED_SECURITY echoed to a client that asked for it")
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

func smbHandshakeIPC(t *testing.T, client net.Conn) (uid, tid uint16) {
	t.Helper()
	negBody := []byte{0x00, 0x0c, 0x00}
	negBody = append(negBody, []byte("\x02NT LM 0.12\x00")...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x72, 0, 0, 1)), negBody...))
	_ = readSMBFrame(t, client)

	ssBody := []byte{
		0x0d, 0xff, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x02, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x73, 0, 0, 2)), ssBody...))
	ssResp := readSMBFrame(t, client)
	uid = binary.LittleEndian.Uint16(ssResp[28:30])
	require.NotZero(t, uid)

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x75, 0, uid, 3)), treeConnectBody(`\\127.0.0.1\IPC$`)...))
	tcResp := readSMBFrame(t, client)
	tid = binary.LittleEndian.Uint16(tcResp[24:26])
	require.NotZero(t, tid)
	return uid, tid
}

// treeConnectBody builds a Unicode SMB_COM_TREE_CONNECT_ANDX request body.
func treeConnectBody(path string) []byte {
	dataBytes := append([]byte{0x00}, encodeSMBPath(path)...)
	dataBytes = append(dataBytes, []byte("?????\x00")...)
	tcBody := []byte{
		0x04, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	}
	binary.LittleEndian.PutUint16(tcBody[9:11], uint16(len(dataBytes)))
	return append(tcBody, dataBytes...)
}

func ntCreateAndXBody(name string) []byte {
	encoded := encodeSMBPath(name)
	words := make([]byte, 48)
	words[0] = 0xff
	binary.LittleEndian.PutUint16(words[5:7], uint16(len(encoded)))
	body := append([]byte{0x18}, words...)
	var bc [2]byte
	binary.LittleEndian.PutUint16(bc[:], uint16(len(encoded)))
	// Unicode Name is aligned to a 2-byte boundary relative to the SMB header.
	off := 1 + 48 + 2
	if (32+off)%2 != 0 {
		body = append(body, bc[:]...)
		body = append(body, 0)
		body = append(body, encoded...)
		binary.LittleEndian.PutUint16(body[1+48:1+50], uint16(1+len(encoded)))
		return body
	}
	body = append(body, bc[:]...)
	body = append(body, encoded...)
	return body
}

func TestHandleSMBNtCreateAndXPipe(t *testing.T) {
	client, hp, done := startHandleSMB(t)
	uid, tid := smbHandshakeIPC(t, client)

	body := ntCreateAndXBody(`\svcctl`)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdNtCreateAndX, tid, uid, 4)), body...))
	createResp := readSMBFrame(t, client)
	require.Equal(t, byte(smb.CmdNtCreateAndX), createResp[4])
	require.Equal(t, [4]byte{}, [4]byte(createResp[5:9]))
	require.Equal(t, byte(34), createResp[32])
	fid := binary.LittleEndian.Uint16(createResp[38:40])
	require.NotZero(t, fid)
	require.Equal(t, uint32(1), binary.LittleEndian.Uint32(createResp[40:44]), "FILE_OPENED")

	// Follow-on read still possible after a protocol-valid Create AndX.
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x71, tid, uid, 5)), 0x00, 0x00, 0x00))
	tdResp := readSMBFrame(t, client)
	require.Equal(t, byte(0x71), tdResp[4])
	require.Equal(t, [4]byte{}, [4]byte(tdResp[5:9]))

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)

	var sawCreateRead, sawCreateWrite bool
	for _, f := range frames {
		if f.Direction == "read" && f.Header.Command == smb.CmdNtCreateAndX {
			require.Equal(t, "SMB_COM_NT_CREATE_ANDX", f.Command)
			require.Equal(t, `\svcctl`, f.Path)
			sawCreateRead = true
		}
		if f.Direction == "write" && f.Header.Command == smb.CmdNtCreateAndX {
			require.Equal(t, "SMB_COM_NT_CREATE_ANDX", f.Command)
			require.Equal(t, byte(34), f.Payload[4+32])
			gotFID := binary.LittleEndian.Uint16(f.Payload[4+38 : 4+40])
			require.Equal(t, fid, gotFID)
			require.NotZero(t, gotFID)
			sawCreateWrite = true
		}
	}
	require.True(t, sawCreateRead, "expected NT Create AndX read")
	require.True(t, sawCreateWrite, "expected NT Create AndX write with WordCount 34")
}

func TestHandleSMBDecodedShareAndTrans2(t *testing.T) {
	client, hp, done := startHandleSMB(t)
	uid, tid := smbHandshakeIPC(t, client)
	trans2, err := hex.DecodeString(
		"0f0c00000001000000000000000134ee0000000c00420000004e0001000e00" +
			"0d0000000000000000000000000000")
	require.NoError(t, err)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdTransaction2, tid, uid, 0x41)), trans2...))
	resp := readSMBFrame(t, client)
	require.Equal(t, byte(smb.CmdTransaction2), resp[4])
	require.Equal(t, [4]byte{0x02, 0x00, 0x00, 0xc0}, [4]byte(resp[5:9]))

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)
	var sawTree, sawTrans2Read, sawTrans2Write bool
	for _, f := range frames {
		if f.Direction == "read" && f.Command == "SMB_COM_TREE_CONNECT_ANDX" {
			require.Equal(t, "IPC$", f.Path)
			sawTree = true
		}
		if f.Direction == "read" && f.Command == "SMB_COM_TRANSACTION2" {
			require.Equal(t, "TRANS2_SESSION_SETUP", f.Setup)
			sawTrans2Read = true
		}
		if f.Direction == "write" && f.Command == "SMB_COM_TRANSACTION2" {
			require.Equal(t, "STATUS_NOT_IMPLEMENTED", f.Status)
			require.Equal(t, uint32(0xc0000002), f.NTStatus)
			sawTrans2Write = true
		}
	}
	require.True(t, sawTree)
	require.True(t, sawTrans2Read)
	require.True(t, sawTrans2Write)
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

func TestHandleSMBNtTransactAndTrans2Secondary(t *testing.T) {
	client, hp, done := startHandleSMB(t)

	ntBody := make([]byte, 16)
	ntBody[0] = 19 // WordCount
	binary.LittleEndian.PutUint32(ntBody[8:12], 0x103d0)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdNtTransact, 1, 1, 1)), ntBody...))
	resp := readSMBFrame(t, client)
	require.Equal(t, byte(smb.CmdNtTransact), resp[4])
	require.Equal(t, [4]byte{}, [4]byte(resp[5:9]))

	secBody := make([]byte, 1+9*2+2)
	secBody[0] = 9
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdTransaction2Secondary, 1, 1, 2)), secBody...))

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)

	var sawNT, sawSec bool
	for _, f := range frames {
		if f.Direction == "read" && f.Header.Command == smb.CmdNtTransact {
			require.Equal(t, "SMB_COM_NT_TRANSACT", f.Command)
			require.Equal(t, uint32(0x103d0), f.TotalDataCount)
			sawNT = true
		}
		if f.Direction == "read" && f.Header.Command == smb.CmdTransaction2Secondary {
			require.Equal(t, "SMB_COM_TRANSACTION2_SECONDARY", f.Command)
			sawSec = true
		}
		if f.Direction == "write" && f.Header.Command == smb.CmdTransaction2Secondary {
			t.Fatal("TRANSACTION2_SECONDARY must not get a reply")
		}
	}
	require.True(t, sawNT, "expected NT_TRANSACT read with TotalDataCount")
	require.True(t, sawSec, "expected TRANSACTION2_SECONDARY read")
}

func smbTrans2SecondaryBody(disp, count uint16) []byte {
	body := make([]byte, 1+9*2+2)
	body[0] = 9
	binary.LittleEndian.PutUint16(body[11:13], count)
	binary.LittleEndian.PutUint16(body[15:17], disp)
	return body
}

func TestHandleSMBNtTransactCompletesOnFinalSecondary(t *testing.T) {
	client, hp, done := startHandleSMB(t)

	const total = 8192
	ntBody := make([]byte, 16)
	ntBody[0] = 19
	binary.LittleEndian.PutUint32(ntBody[8:12], total)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdNtTransact, 1, 1, 1)), ntBody...))
	ntResp := readSMBFrame(t, client)
	require.Equal(t, byte(smb.CmdNtTransact), ntResp[4])

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdTransaction2Secondary, 1, 1, 2)), smbTrans2SecondaryBody(0, 4096)...))
	require.NoError(t, client.SetReadDeadline(time.Now().Add(150*time.Millisecond)))
	var nb [4]byte
	_, err := io.ReadFull(client, nb[:])
	require.ErrorIs(t, err, os.ErrDeadlineExceeded, "middle fragment must get no reply")
	require.NoError(t, client.SetReadDeadline(time.Time{}))

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdTransaction2Secondary, 1, 1, 3)), smbTrans2SecondaryBody(4096, 4096)...))
	secResp := readSMBFrame(t, client)
	require.Equal(t, byte(smb.CmdTransaction2Secondary), secResp[4])
	require.Equal(t, []byte{0x0d, 0x00, 0x00, 0xc0}, secResp[5:9])

	echoData := []byte("after")
	echoBody := []byte{0x01, 0x01, 0x00}
	var bc [2]byte
	binary.LittleEndian.PutUint16(bc[:], uint16(len(echoData)))
	echoBody = append(echoBody, bc[:]...)
	echoBody = append(echoBody, echoData...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdEcho, 1, 1, 4)), echoBody...))
	echoResp := readSMBFrame(t, client)
	require.Equal(t, byte(smb.CmdEcho), echoResp[4])
	require.Equal(t, echoData, echoResp[37:])

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)

	var completeWrites int
	for _, f := range frames {
		if f.Direction == "write" && f.Header.Command == smb.CmdTransaction2Secondary {
			require.Equal(t, "STATUS_INVALID_PARAMETER", f.Status)
			completeWrites++
		}
	}
	require.Equal(t, 1, completeWrites, "exactly one completion reply")
}

func TestHandleSMBSecondaryWithoutNtTransactGetsNoReply(t *testing.T) {
	client, hp, done := startHandleSMB(t)

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdTransaction2Secondary, 1, 1, 1)), smbTrans2SecondaryBody(0, 4096)...))
	require.NoError(t, client.SetReadDeadline(time.Now().Add(150*time.Millisecond)))
	var nb [4]byte
	_, err := io.ReadFull(client, nb[:])
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, client.SetReadDeadline(time.Time{}))

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)
	for _, f := range frames {
		if f.Direction == "write" && f.Header.Command == smb.CmdTransaction2Secondary {
			t.Fatal("orphan secondary must not get a reply")
		}
	}
	require.Equal(t, "read", frames[0].Direction)
	require.Equal(t, "SMB_COM_TRANSACTION2_SECONDARY", frames[0].Command)
}

func TestHandleSMBEcho(t *testing.T) {
	client, hp, done := startHandleSMB(t)

	echoData := []byte("JlJmIhClBsr")
	body := []byte{0x01, 0x01, 0x00} // WordCount=1, EchoCount=1
	var bc [2]byte
	binary.LittleEndian.PutUint16(bc[:], uint16(len(echoData)))
	body = append(body, bc[:]...)
	body = append(body, echoData...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdEcho, 1, 1, 1)), body...))
	resp := readSMBFrame(t, client)
	require.Equal(t, byte(smb.CmdEcho), resp[4])
	require.Equal(t, [4]byte{}, [4]byte(resp[5:9]))
	require.Equal(t, byte(1), resp[32])
	require.Equal(t, uint16(1), binary.LittleEndian.Uint16(resp[33:35]))
	require.Equal(t, uint16(len(echoData)), binary.LittleEndian.Uint16(resp[35:37]))
	require.Equal(t, echoData, resp[37:])

	ev := finishHandleSMB(t, client, done, hp)
	frames, ok := ev.decoded.([]parsedSMB)
	require.True(t, ok)
	var sawRead, sawWrite bool
	for _, f := range frames {
		if f.Direction == "read" && f.Command == "SMB_COM_ECHO" {
			sawRead = true
		}
		if f.Direction == "write" && f.Command == "SMB_COM_ECHO" {
			require.Equal(t, "STATUS_SUCCESS", f.Status)
			sawWrite = true
		}
	}
	require.True(t, sawRead)
	require.True(t, sawWrite)
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

func TestHandleSMBStoresReassembledTransaction(t *testing.T) {
	var stored []byte
	orig := smbStore
	smbStore = func(data []byte, folder string) (string, error) {
		stored = append([]byte(nil), data...)
		return "", nil
	}
	t.Cleanup(func() { smbStore = orig })

	client, hp, done := startHandleSMB(t)

	ntBody := make([]byte, 36, 40)
	ntBody[0] = 19
	binary.LittleEndian.PutUint32(ntBody[8:12], 8)
	binary.LittleEndian.PutUint32(ntBody[28:32], 4)
	binary.LittleEndian.PutUint32(ntBody[32:36], 32+36)
	ntBody = append(ntBody, "AAAA"...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdNtTransact, 1, 1, 1)), ntBody...))
	readSMBFrame(t, client)

	secBody := smbTrans2SecondaryBody(4, 4)
	binary.LittleEndian.PutUint16(secBody[13:15], 32+uint16(len(secBody)))
	secBody = append(secBody, "BBBB"...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdTransaction2Secondary, 1, 1, 2)), secBody...))
	readSMBFrame(t, client)

	ev := finishHandleSMB(t, client, done, hp)
	require.Equal(t, []byte("AAAABBBB"), stored)
	frames := ev.decoded.([]parsedSMB)
	var hashed int
	for _, f := range frames {
		if f.PayloadHash != "" {
			require.Equal(t, smb.CmdNtTransact, int(f.Header.Command))
			require.Equal(t, helpers.SHA256Hex([]byte("AAAABBBB")), f.PayloadHash)
			hashed++
		}
	}
	require.Equal(t, 1, hashed)
}

func TestHandleSMBNetBIOSSessionRequest(t *testing.T) {
	client, hp, done := startHandleSMB(t)
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))

	// Synthetic port 139 session request: called "*SMBSERVER<20>", calling "KALI<00>".
	sessReq, err := hex.DecodeString("81000044" +
		"20434b4644454e4543464445464643464745464643434143414341434143414341" + "00" +
		"20454c4542454d454a43414341434143414341434143414341434143414341414100")
	require.NoError(t, err)
	_, err = client.Write(sessReq)
	require.NoError(t, err)
	resp := make([]byte, 4)
	_, err = io.ReadFull(client, resp)
	require.NoError(t, err)
	require.Equal(t, []byte{0x82, 0x00, 0x00, 0x00}, resp)

	keepAlive := []byte{0x85, 0x00, 0x00, 0x00}
	_, err = client.Write(keepAlive)
	require.NoError(t, err)

	negBody := append([]byte{0x00, 0x0c, 0x00}, []byte("\x02NT LM 0.12\x00")...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x72, 0, 0, 1)), negBody...))
	require.Equal(t, byte(0x72), readSMBFrame(t, client)[4])

	ev := finishHandleSMB(t, client, done, hp)
	frames := ev.decoded.([]parsedSMB)
	require.Len(t, frames, 5)
	require.Equal(t, []parsedSMB{
		{Direction: "read", Command: "NBSS_SESSION_REQUEST", CalledName: "*SMBSERVER", CallingName: "KALI", Payload: sessReq},
		{Direction: "write", Command: "NBSS_POSITIVE_SESSION_RESPONSE", Payload: []byte{0x82, 0x00, 0x00, 0x00}},
		{Direction: "read", Command: "NBSS_SESSION_KEEP_ALIVE", Payload: keepAlive},
	}, frames[:3])
	require.Equal(t, "SMB_COM_NEGOTIATE", frames[3].Command)
	require.Equal(t, "write", frames[4].Direction)
}

func TestHandleSMBMalformedSessionRequestStillAccepted(t *testing.T) {
	client, hp, done := startHandleSMB(t)
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))

	sessReq := []byte{0x81, 0x00, 0x00, 0x02, 0x20, 'A'}
	_, err := client.Write(sessReq)
	require.NoError(t, err)
	resp := make([]byte, 4)
	_, err = io.ReadFull(client, resp)
	require.NoError(t, err)
	require.Equal(t, byte(0x82), resp[0])

	ev := finishHandleSMB(t, client, done, hp)
	frames := ev.decoded.([]parsedSMB)
	require.Len(t, frames, 2)
	require.Equal(t, parsedSMB{Direction: "read", Command: "NBSS_SESSION_REQUEST", Payload: sessReq}, frames[0])
}

func TestHandleSMBRejectsNmapProbeShare(t *testing.T) {
	client, hp, done := startHandleSMB(t)
	uid, tid := smbHandshakeIPC(t, client)

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x75, 0, uid, 4)), treeConnectBody(`\\127.0.0.1\nmap-share-test`)...))
	resp := readSMBFrame(t, client)
	require.Equal(t, [4]byte{0xcc, 0x00, 0x00, 0xc0}, [4]byte(resp[5:9]))
	require.Zero(t, binary.LittleEndian.Uint16(resp[24:26]), "no TID for a missing share")

	// The next real share still gets the next TID.
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x75, 0, uid, 5)), treeConnectBody(`\\127.0.0.1\C$`)...))
	resp = readSMBFrame(t, client)
	require.Equal(t, [4]byte{}, [4]byte(resp[5:9]))
	require.Equal(t, tid+1, binary.LittleEndian.Uint16(resp[24:26]))

	ev := finishHandleSMB(t, client, done, hp)
	frames := ev.decoded.([]parsedSMB)
	require.Len(t, frames, 10)
	require.Equal(t, "read", frames[6].Direction)
	require.Equal(t, "nmap-share-test", frames[6].Path)
	require.Equal(t, "write", frames[7].Direction)
	require.Equal(t, "SMB_COM_TREE_CONNECT_ANDX", frames[7].Command)
	require.Equal(t, "STATUS_BAD_NETWORK_NAME", frames[7].Status)
	require.Equal(t, uint32(0xc00000cc), frames[7].NTStatus)
	require.Equal(t, "C$", frames[8].Path)
	require.Equal(t, "STATUS_SUCCESS", frames[9].Status)
}

// --- helpers for pipe/file/NTLM handler tests ---

func writeAndXBody(fid uint16, data []byte) []byte {
	b := make([]byte, 31)
	b[0] = 14   // WordCount
	b[1] = 0xff // AndXCommand: none
	binary.LittleEndian.PutUint16(b[5:7], fid)
	binary.LittleEndian.PutUint16(b[21:23], uint16(len(data))) // DataLength
	binary.LittleEndian.PutUint16(b[23:25], 63)                // DataOffset from SMB header
	binary.LittleEndian.PutUint16(b[29:31], uint16(len(data))) // ByteCount
	return append(b, data...)
}

func readAndXBody(fid uint16) []byte {
	b := make([]byte, 27)
	b[0] = 12   // WordCount
	b[1] = 0xff // AndXCommand: none
	binary.LittleEndian.PutUint16(b[5:7], fid)
	return b
}

func closeBody(fid uint16) []byte {
	b := make([]byte, 10)
	b[0] = 3 // WordCount
	binary.LittleEndian.PutUint16(b[1:3], fid)
	return b
}

func dcerpcFrameBytes(ptype byte, callID uint32, body []byte) []byte {
	out := make([]byte, 16+len(body))
	out[0] = 5     // version
	out[2] = ptype // PTYPE
	out[3] = 0x03  // first + last fragment
	out[4] = 0x10  // little-endian drep
	binary.LittleEndian.PutUint16(out[8:10], uint16(len(out)))
	binary.LittleEndian.PutUint32(out[12:16], callID)
	copy(out[16:], body)
	return out
}

func dcerpcBind(callID uint32) []byte {
	// srvsvc interface + NDR transfer syntax.
	body := []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0} // max_xmit/recv, assoc
	body = append(body, 0x01, 0x00, 0x00, 0x00)        // n_context_elem + reserved
	body = append(body, 0x00, 0x00, 0x01, 0x00)        // p_cont_id, n_transfer_syn, reserved
	body = append(body, 0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
		0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88) // srvsvc UUID
	body = append(body, 0x03, 0x00, 0x00, 0x00) // interface version 3.0
	body = append(body, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60) // NDR UUID
	body = append(body, 0x02, 0x00, 0x00, 0x00) // transfer version 2.0
	return dcerpcFrameBytes(0x0b, callID, body)
}

func dcerpcRequest(callID uint32, opnum uint16, stub []byte) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], uint32(len(stub))) // alloc_hint
	binary.LittleEndian.PutUint16(body[6:8], opnum)
	return dcerpcFrameBytes(0x00, callID, append(body, stub...))
}

func TestHandleSMBPipeDCERPCBindAndRequest(t *testing.T) {
	var stored [][]byte
	orig := smbStore
	smbStore = func(data []byte, folder string) (string, error) {
		stored = append(stored, append([]byte(nil), data...))
		return helpers.SHA256Hex(data), nil
	}
	t.Cleanup(func() { smbStore = orig })

	client, hp, done := startHandleSMB(t)
	uid, tid := smbHandshakeIPC(t, client)

	// Open \svcctl, bind, then issue one request.
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdNtCreateAndX, tid, uid, 4)), ntCreateAndXBody(`\svcctl`)...))
	fid := binary.LittleEndian.Uint16(readSMBFrame(t, client)[38:40])

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdWriteAndX, tid, uid, 5)), writeAndXBody(fid, dcerpcBind(0x11))...))
	readSMBFrame(t, client)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdReadAndX, tid, uid, 6)), readAndXBody(fid)...))
	bindAck := readSMBFrame(t, client)
	require.True(t, bytes.Contains(bindAck, []byte{0x05, 0x00, 0x0c}), "DCERPC bind_ack returned")

	stub := []byte("OpenSCManager-args")
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdWriteAndX, tid, uid, 7)), writeAndXBody(fid, dcerpcRequest(0x11, 15, stub))...))
	readSMBFrame(t, client)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdReadAndX, tid, uid, 8)), readAndXBody(fid)...))
	fault := readSMBFrame(t, client)
	require.True(t, bytes.Contains(fault, []byte{0x05, 0x00, 0x03}), "DCERPC fault returned (no RPC service emulated)")

	ev := finishHandleSMB(t, client, done, hp)
	frames := ev.decoded.([]parsedSMB)

	var sawBind, sawReq bool
	for _, f := range frames {
		if f.DCERPC == "DCERPC_BIND" {
			require.Equal(t, "4b324fc8-1670-01d3-1278-5a47bf6ee188", f.Interface)
			require.Equal(t, "3.0", f.InterfaceVer)
			sawBind = true
		}
		if f.DCERPC == "DCERPC_REQUEST" {
			require.NotNil(t, f.Opnum)
			require.Equal(t, uint16(15), *f.Opnum)
			require.Equal(t, "4b324fc8-1670-01d3-1278-5a47bf6ee188", f.Interface)
			require.Equal(t, helpers.SHA256Hex(stub), f.PayloadHash)
			sawReq = true
		}
	}
	require.True(t, sawBind, "bind frame tagged")
	require.True(t, sawReq, "request frame tagged with opnum + stub hash")
	require.Equal(t, [][]byte{stub}, stored, "only the request stub was stored")
}

func TestHandleSMBFileUploadCaptured(t *testing.T) {
	var stored []byte
	orig := smbStore
	smbStore = func(data []byte, folder string) (string, error) {
		stored = append([]byte(nil), data...)
		return helpers.SHA256Hex(data), nil
	}
	t.Cleanup(func() { smbStore = orig })

	client, hp, done := startHandleSMB(t)
	uid := smbHandshakeDiskShare(t, client)
	tid := uint16(1) // the disk share's TID

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdNtCreateAndX, tid, uid, 4)), ntCreateAndXBody(`\payload.exe`)...))
	createResp := readSMBFrame(t, client)
	require.Equal(t, uint16(0), binary.LittleEndian.Uint16(createResp[96:98]), "disk file, not pipe")
	fid := binary.LittleEndian.Uint16(createResp[38:40])

	upload := bytes.Repeat([]byte("MZ..payload.."), 100)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdWriteAndX, tid, uid, 5)), writeAndXBody(fid, upload[:600])...))
	readSMBFrame(t, client)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdWriteAndX, tid, uid, 6)), writeAndXBody(fid, upload[600:])...))
	readSMBFrame(t, client)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdClose, tid, uid, 7)), closeBody(fid)...))
	readSMBFrame(t, client)

	ev := finishHandleSMB(t, client, done, hp)
	require.Equal(t, upload, stored, "both write fragments reassembled on close")

	frames := ev.decoded.([]parsedSMB)
	var tagged bool
	for _, f := range frames {
		if f.Direction == "read" && f.Header.Command == smb.CmdNtCreateAndX {
			require.Equal(t, `\payload.exe`, f.Path)
			require.Equal(t, helpers.SHA256Hex(upload), f.PayloadHash)
			tagged = true
		}
	}
	require.True(t, tagged, "upload hash set on the NT Create frame")
}

// smbHandshakeDiskShare negotiates, sets up a session, and tree-connects to a
// disk share (C$), returning the session UID. The share gets TID 1.
func smbHandshakeDiskShare(t *testing.T, client net.Conn) (uid uint16) {
	t.Helper()
	negBody := append([]byte{0x00, 0x0c, 0x00}, []byte("\x02NT LM 0.12\x00")...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x72, 0, 0, 1)), negBody...))
	_ = readSMBFrame(t, client)

	ssBody := []byte{
		0x0d, 0xff, 0x00, 0x00, 0x00, 0xff, 0xff, 0x02, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x73, 0, 0, 2)), ssBody...))
	uid = binary.LittleEndian.Uint16(readSMBFrame(t, client)[28:30])
	require.NotZero(t, uid)

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x75, 0, uid, 3)), treeConnectBody(`\\127.0.0.1\C$`)...))
	require.NotZero(t, binary.LittleEndian.Uint16(readSMBFrame(t, client)[24:26]))
	return uid
}

func sessionSetupESecBody(blob []byte) []byte {
	b := make([]byte, 27)
	b[0] = 12                                                  // WordCount
	b[1] = 0xff                                                // AndXCommand: none
	binary.LittleEndian.PutUint16(b[15:17], uint16(len(blob))) // SecurityBlobLength
	binary.LittleEndian.PutUint16(b[25:27], uint16(len(blob))) // ByteCount
	return append(b, blob...)
}

func ntlmType1() []byte {
	m := make([]byte, 16)
	copy(m, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(m[8:12], 1)           // NEGOTIATE
	binary.LittleEndian.PutUint32(m[12:16], 0x00000201) // Unicode | NTLM
	return m
}

func ntlmType3(domain, user, workstation string) []byte {
	m := make([]byte, 64)
	copy(m, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(m[8:12], 3)           // AUTHENTICATE
	binary.LittleEndian.PutUint32(m[60:64], 0x00000001) // NEGOTIATE_UNICODE
	payload := []byte{}
	put := func(descOff int, s string) {
		enc := make([]byte, 0, len(s)*2)
		for _, r := range s {
			enc = append(enc, byte(r), byte(r>>8))
		}
		off := 64 + len(payload)
		binary.LittleEndian.PutUint16(m[descOff:], uint16(len(enc)))
		binary.LittleEndian.PutUint16(m[descOff+2:], uint16(len(enc)))
		binary.LittleEndian.PutUint32(m[descOff+4:], uint32(off))
		payload = append(payload, enc...)
	}
	// Fake NT response buffer (never parsed), then the identity fields.
	nt := bytes.Repeat([]byte{0xAA}, 24)
	binary.LittleEndian.PutUint16(m[20:], uint16(len(nt)))
	binary.LittleEndian.PutUint16(m[22:], uint16(len(nt)))
	binary.LittleEndian.PutUint32(m[24:], 64)
	payload = append(payload, nt...)
	put(28, domain)
	put(36, user)
	put(44, workstation)
	return append(m, payload...)
}

func TestHandleSMBNTLMSSPSessionSetup(t *testing.T) {
	client, hp, done := startHandleSMB(t)

	// Negotiate with extended security advertised.
	negBody := append([]byte{0x00, 0x0c, 0x00}, []byte("\x02NT LM 0.12\x00")...)
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x72, 0, 0, 1)), negBody...))
	negResp := readSMBFrame(t, client)
	require.NotZero(t, binary.LittleEndian.Uint16(negResp[10:12])&0x0800, "ext-sec echoed")

	// Step 1: Type 1 -> challenge with STATUS_MORE_PROCESSING_REQUIRED.
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x73, 0, 0, 2)), sessionSetupESecBody(ntlmType1())...))
	chalResp := readSMBFrame(t, client)
	require.Equal(t, [4]byte{0x16, 0x00, 0x00, 0xc0}, [4]byte(chalResp[5:9]), "STATUS_MORE_PROCESSING_REQUIRED")
	require.True(t, bytes.Contains(chalResp, []byte("NTLMSSP\x00")), "challenge carries NTLMSSP")
	uid := binary.LittleEndian.Uint16(chalResp[28:30])
	require.NotZero(t, uid)

	// Step 2: Type 3 -> success, identity recorded.
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(0x73, 0, uid, 3)), sessionSetupESecBody(ntlmType3("CORP", "operator", "WS7"))...))
	okResp := readSMBFrame(t, client)
	require.Equal(t, [4]byte{}, [4]byte(okResp[5:9]), "STATUS_SUCCESS")

	ev := finishHandleSMB(t, client, done, hp)
	frames := ev.decoded.([]parsedSMB)

	var auth parsedSMB
	for _, f := range frames {
		if f.Direction == "read" && f.Account == "operator" {
			auth = f
		}
	}
	require.Equal(t, "operator", auth.Account)
	require.Equal(t, "CORP", auth.Domain)
	require.Equal(t, "WS7", auth.Workstation)

	// No credential material leaks into decoded string fields.
	require.NotContains(t, auth.Status, "\xaa")
	require.Empty(t, auth.PayloadHash, "NTLM responses are not stored")
}

func TestHandleSMB2NegotiateAndSessionSetupNTLM(t *testing.T) {
	client, hp, done := startHandleSMB(t)
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))

	// SMB2 Negotiate: response must advertise an NTLMSSP SPNEGO blob.
	neg := make([]byte, 64)
	neg[0] = 0xfe
	copy(neg[1:4], []byte("SMB"))
	binary.LittleEndian.PutUint16(neg[4:6], 64)
	binary.LittleEndian.PutUint16(neg[12:14], smb.SMB2CmdNegotiate)
	writeSMBFrame(t, client, neg)
	negResp := readSMBFrame(t, client)
	require.True(t, bytes.Contains(negResp, []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}), "SPNEGO OID in negotiate")

	// SMB2 Session Setup with an NTLMSSP Type 1 -> MORE_PROCESSING + challenge.
	ss := make([]byte, 64+24)
	ss[0] = 0xfe
	copy(ss[1:4], []byte("SMB"))
	binary.LittleEndian.PutUint16(ss[4:6], 64)
	binary.LittleEndian.PutUint16(ss[12:14], smb.SMB2CmdSessionSetup)
	binary.LittleEndian.PutUint16(ss[64:66], 25)   // StructureSize
	binary.LittleEndian.PutUint16(ss[76:78], 0x58) // SecurityBufferOffset
	binary.LittleEndian.PutUint16(ss[78:80], 16)   // SecurityBufferLength
	ss = append(ss, ntlmType1()...)
	writeSMBFrame(t, client, ss)
	ssResp := readSMBFrame(t, client)
	require.Equal(t, uint32(0xc0000016), binary.LittleEndian.Uint32(ssResp[8:12]), "MORE_PROCESSING")
	require.True(t, bytes.Contains(ssResp, []byte("NTLMSSP\x00")), "challenge carries NTLMSSP")

	ev := finishHandleSMB(t, client, done, hp)
	frames := ev.decoded.([]parsedSMB)
	require.Equal(t, "SMB2_NEGOTIATE", frames[0].Command)
	require.Equal(t, "SMB2_SESSION_SETUP", frames[2].Command)
}

func TestHandleSMBFileUploadCapped(t *testing.T) {
	origCap := maxSMBFileBuffer
	maxSMBFileBuffer = 1024
	t.Cleanup(func() { maxSMBFileBuffer = origCap })

	var stored []byte
	origStore := smbStore
	smbStore = func(data []byte, folder string) (string, error) {
		stored = append([]byte(nil), data...)
		return helpers.SHA256Hex(data), nil
	}
	t.Cleanup(func() { smbStore = origStore })

	client, hp, done := startHandleSMB(t)
	uid := smbHandshakeDiskShare(t, client)
	tid := uint16(1)

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdNtCreateAndX, tid, uid, 4)), ntCreateAndXBody(`\big.bin`)...))
	fid := binary.LittleEndian.Uint16(readSMBFrame(t, client)[38:40])

	// Two 800-byte writes: the handle buffer must stop at the 1024 cap.
	chunk := bytes.Repeat([]byte("A"), 800)
	for i, mid := 0, uint16(5); i < 2; i, mid = i+1, mid+1 {
		writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdWriteAndX, tid, uid, mid)), writeAndXBody(fid, chunk)...))
		readSMBFrame(t, client)
	}
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdClose, tid, uid, 9)), closeBody(fid)...))
	readSMBFrame(t, client)

	finishHandleSMB(t, client, done, hp)
	require.Len(t, stored, 1024, "upload buffer bounded by the cap")
}

func TestHandleSMBPipeNonDCERPCDropped(t *testing.T) {
	client, hp, done := startHandleSMB(t)
	uid, tid := smbHandshakeIPC(t, client)

	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdNtCreateAndX, tid, uid, 4)), ntCreateAndXBody(`\svcctl`)...))
	fid := binary.LittleEndian.Uint16(readSMBFrame(t, client)[38:40])

	// Junk written to the pipe must not crash or produce a DCERPC frame.
	writeSMBFrame(t, client, append(smbHeaderBytes(t, smbReqHeader(smb.CmdWriteAndX, tid, uid, 5)), writeAndXBody(fid, bytes.Repeat([]byte{0x99}, 64))...))
	readSMBFrame(t, client)

	ev := finishHandleSMB(t, client, done, hp)
	for _, f := range ev.decoded.([]parsedSMB) {
		require.Empty(t, f.DCERPC, "non-DCERPC pipe data is not tagged")
	}
}
