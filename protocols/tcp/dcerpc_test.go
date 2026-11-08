package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/epm"
	"github.com/mushorg/glutton/protocols/tcp/smb"
	"github.com/stretchr/testify/require"
)

// Captured: run-1794097956-1.jsonl event #5 (Shodan, 24.199.126.56 -> tcp/135,
// 2026-11-08T00:32:45Z). A bind for the endpoint mapper v3.0 with NDR, call_id 1.
var dcerpcEPMBind = []byte{
	0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
	0x03, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
	0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
}

// Same event: ept_lookup (opnum 2), call_id 1 (reused from the bind),
// p_cont_id 0, max_ents 500.
var dcerpcEPMLookup = []byte{
	0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf4, 0x01, 0x00, 0x00,
}

func runDCERPC(t *testing.T, port uint16, send func(c net.Conn)) producedTCP {
	t.Helper()
	client, serverConn := net.Pipe()
	defer client.Close()
	hp := newFakeHoneypot()
	done := make(chan error, 1)
	go func() {
		done <- HandleDCERPC(context.Background(), serverConn, connection.Metadata{TargetPort: port}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	send(client)
	_, _ = io.ReadAll(client)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := waitProduced(t, hp)
	select {
	case extra := <-hp.produced:
		t.Fatalf("expected a single produced event, got another: %+v", extra)
	default:
	}
	require.Equal(t, "dcerpc", produced.protocol)
	return produced
}

func readDCERPCPDU(t *testing.T, c net.Conn) []byte {
	t.Helper()
	head := make([]byte, smb.HeaderLen)
	_, err := io.ReadFull(c, head)
	require.NoError(t, err)
	pdu := make([]byte, binary.LittleEndian.Uint16(head[8:10]))
	copy(pdu, head)
	_, err = io.ReadFull(c, pdu[smb.HeaderLen:])
	require.NoError(t, err)
	return pdu
}

func u16p(v uint16) *uint16 { return &v }

func TestHandleDCERPCEndpointMapperLookup(t *testing.T) {
	var bindAck, resp []byte
	produced := runDCERPC(t, 135, func(c net.Conn) {
		_, err := c.Write(dcerpcEPMBind)
		require.NoError(t, err)
		bindAck = readDCERPCPDU(t, c)
		_, err = c.Write(dcerpcEPMLookup)
		require.NoError(t, err)
		resp = readDCERPCPDU(t, c)
		require.NoError(t, c.Close())
	})

	// bind_ack: call_id 1, secondary address "135", context 0 accepted with NDR
	ctxs, ok := smb.ParseBind(dcerpcEPMBind)
	require.True(t, ok)
	require.Equal(t, smb.BuildBindAck(1, "135", ctxs), bindAck)
	require.Equal(t, byte(0x0c), bindAck[2])
	require.Equal(t, []byte{0x04, 0x00, '1', '3', '5', 0x00}, bindAck[24:30])

	// response (not a second bind_ack): call_id 1, p_cont_id 0, empty result
	want := append([]byte{
		0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, epm.BuildEmptyResult(500)...)
	require.Equal(t, want, resp)

	require.Equal(t, dcerpcEPMBind, produced.payload)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedDCERPC{
		{Direction: "read", DCERPC: "DCERPC_BIND", Command: "DCERPC_BIND", CallID: 1, Interface: epm.UUID, InterfaceVersion: "3.0", Payload: dcerpcEPMBind},
		{Direction: "write", DCERPC: "DCERPC_BIND_ACK", CallID: 1, Status: "bind_ack", Payload: bindAck},
		{Direction: "read", DCERPC: "DCERPC_REQUEST", Command: "ept_lookup", CallID: 1, Interface: epm.UUID, InterfaceVersion: "3.0", Opnum: u16p(2), Payload: dcerpcEPMLookup},
		{Direction: "write", DCERPC: "DCERPC_RESPONSE", CallID: 1, Status: "EPT_S_NOT_REGISTERED", Payload: resp},
	}, produced.decoded)
}

func epmRequest(callID uint32, ctxID, opnum uint16, stub []byte) []byte {
	pdu := make([]byte, 24, 24+len(stub))
	pdu[0], pdu[2], pdu[3], pdu[4] = 5, 0x00, 0x03, 0x10
	binary.LittleEndian.PutUint16(pdu[8:10], uint16(24+len(stub)))
	binary.LittleEndian.PutUint32(pdu[12:16], callID)
	binary.LittleEndian.PutUint32(pdu[16:20], uint32(len(stub)))
	binary.LittleEndian.PutUint16(pdu[20:22], ctxID)
	binary.LittleEndian.PutUint16(pdu[22:24], opnum)
	return append(pdu, stub...)
}

func TestHandleDCERPCFaults(t *testing.T) {
	unbound := epmRequest(3, 7, 2, nil)   // context 7 was never bound
	badOp := epmRequest(4, 0, 9, nil)     // opnum outside the EPM interface
	shortStub := epmRequest(5, 0, 2, nil) // ept_lookup without its stub
	var replies [][]byte
	produced := runDCERPC(t, 49664, func(c net.Conn) {
		_, err := c.Write(dcerpcEPMBind)
		require.NoError(t, err)
		ack := readDCERPCPDU(t, c)
		require.Equal(t, []byte{0x06, 0x00, '4', '9', '6', '6', '4', 0x00}, ack[24:32], "secondary address is the port")
		for _, req := range [][]byte{unbound, badOp, shortStub} {
			_, err = c.Write(req)
			require.NoError(t, err)
			replies = append(replies, readDCERPCPDU(t, c))
		}
		require.NoError(t, c.Close())
	})
	require.Equal(t, smb.BuildFaultFor(3, 7, ncaUnknownIf), replies[0])
	require.Equal(t, smb.BuildFaultFor(4, 0, ncaOpRangeError), replies[1])
	require.Equal(t, smb.BuildFaultFor(5, 0, smb.FaultNDR), replies[2])
	require.Equal(t, byte(0x03), replies[0][2])
	require.Equal(t, []byte{0x07, 0x00}, replies[0][20:22], "p_cont_id echoed")

	events := produced.decoded.([]parsedDCERPC)
	require.Len(t, events, 8)
	require.Equal(t, parsedDCERPC{Direction: "read", DCERPC: "DCERPC_REQUEST", Command: "DCERPC_REQUEST", CallID: 3, Opnum: u16p(2), Payload: unbound}, events[2])
	require.Equal(t, parsedDCERPC{Direction: "write", DCERPC: "DCERPC_FAULT", CallID: 3, Status: "nca_s_unknown_if", Payload: replies[0]}, events[3])
	require.Equal(t, "nca_s_op_rng_error", events[5].Status)
	require.Equal(t, "ept_lookup", events[6].Command)
	require.Equal(t, "nca_s_fault_ndr", events[7].Status)
}

func TestHandleDCERPCOtherInterfaceFaults(t *testing.T) {
	// bind IOXIDResolver (99fcfec4-5260-101b-bbcb-00aa0021347a v0.0) and call
	// ServerAlive2 (opnum 5): accepted, then faulted, never answered
	bind := append([]byte(nil), dcerpcEPMBind...)
	copy(bind[32:48], []byte{0xc4, 0xfe, 0xfc, 0x99, 0x60, 0x52, 0x1b, 0x10, 0xbb, 0xcb, 0x00, 0xaa, 0x00, 0x21, 0x34, 0x7a})
	binary.LittleEndian.PutUint32(bind[48:52], 0)
	req := epmRequest(2, 0, 5, nil)
	var fault []byte
	produced := runDCERPC(t, 135, func(c net.Conn) {
		_, err := c.Write(bind)
		require.NoError(t, err)
		readDCERPCPDU(t, c)
		_, err = c.Write(req)
		require.NoError(t, err)
		fault = readDCERPCPDU(t, c)
		require.NoError(t, c.Close())
	})
	require.Equal(t, smb.BuildFaultFor(2, 0, smb.FaultNDR), fault)
	events := produced.decoded.([]parsedDCERPC)
	require.Equal(t, "99fcfec4-5260-101b-bbcb-00aa0021347a", events[0].Interface)
	require.Equal(t, "99fcfec4-5260-101b-bbcb-00aa0021347a", events[2].Interface)
	require.Equal(t, "DCERPC_REQUEST", events[2].Command)
	require.Equal(t, "nca_s_fault_ndr", events[3].Status)
}

func TestHandleDCERPCNotRPCCloses(t *testing.T) {
	junk := []byte("GET / HTTP/1.0\r\n") // one header's worth of bytes
	produced := runDCERPC(t, 135, func(c net.Conn) {
		_, err := c.Write(junk)
		require.NoError(t, err)
	})
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
	require.Equal(t, []parsedDCERPC{{Direction: "read", Payload: junk}}, produced.decoded)
}

func TestHandleDCERPCTruncatedPDU(t *testing.T) {
	// the header promises 72 bytes; the client hangs up after 20
	produced := runDCERPC(t, 135, func(c net.Conn) {
		_, err := c.Write(dcerpcEPMBind[:20])
		require.NoError(t, err)
		require.NoError(t, c.Close())
	})
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, []parsedDCERPC{{Direction: "read", Payload: dcerpcEPMBind[:20]}}, produced.decoded)
}

func TestHandleDCERPCUnhandledPDUType(t *testing.T) {
	// an alter_context is recorded with its type and the association dropped
	alter := append([]byte(nil), dcerpcEPMBind...)
	alter[2] = 0x0e
	produced := runDCERPC(t, 135, func(c net.Conn) {
		_, err := c.Write(alter)
		require.NoError(t, err)
	})
	require.Equal(t, []parsedDCERPC{{Direction: "read", DCERPC: "DCERPC_0x0E", Command: "DCERPC_0x0E", CallID: 1, Payload: alter}}, produced.decoded)
}

func TestHandleDCERPCMaxPDUs(t *testing.T) {
	produced := runDCERPC(t, 135, func(c net.Conn) {
		for range maxDCERPCPDUs {
			_, err := c.Write(dcerpcEPMBind)
			require.NoError(t, err)
			readDCERPCPDU(t, c)
		}
	})
	require.Equal(t, connection.EndMaxFrames, produced.endReason)
	require.Len(t, produced.decoded.([]parsedDCERPC), 2*maxDCERPCPDUs)
}

func TestLooksLikeDCERPC(t *testing.T) {
	require.True(t, smb.LooksLikeDCERPC(dcerpcEPMBind))
	require.True(t, smb.LooksLikeDCERPC(dcerpcEPMLookup))
	require.False(t, smb.LooksLikeDCERPC(dcerpcEPMBind[:12]))
	require.False(t, smb.LooksLikeDCERPC([]byte{0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}))
}
