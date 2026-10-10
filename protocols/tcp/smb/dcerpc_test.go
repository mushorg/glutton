package smb

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// srvsvc abstract syntax 4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0 and the NDR
// transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0, in wire order.
var (
	srvsvcUUID = [16]byte{0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
		0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88}
	ndrUUID = [16]byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
)

func buildBindPDU(callID uint32) []byte {
	body := []byte{0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00} // max_xmit/recv, assoc
	body = append(body, 0x01, 0x00, 0x00, 0x00)                    // n_context_elem + reserved
	body = append(body, 0x00, 0x00)                                // p_cont_id
	body = append(body, 0x01, 0x00)                                // n_transfer_syn + reserved
	body = append(body, srvsvcUUID[:]...)
	body = append(body, 0x03, 0x00, 0x00, 0x00) // abstract version 3.0
	body = append(body, ndrUUID[:]...)
	body = append(body, 0x02, 0x00, 0x00, 0x00) // transfer version 2.0
	return dcerpcFrame(dcerpcPTypeBind, callID, body)
}

func TestParseBind(t *testing.T) {
	ctxs, ok := ParseBind(buildBindPDU(0x2a))
	require.True(t, ok)
	require.Len(t, ctxs, 1)
	require.Equal(t, "4b324fc8-1670-01d3-1278-5a47bf6ee188", ctxs[0].InterfaceUUID())
	require.Equal(t, "3.0", ctxs[0].InterfaceVersion())
	require.Equal(t, append(append([]byte{}, ndrUUID[:]...), 0x02, 0x00, 0x00, 0x00), ctxs[0].TransferSyntax[:])
}

func TestParseBindMalformed(t *testing.T) {
	_, ok := ParseBind([]byte{0x05, 0x00, 0x0b})
	require.False(t, ok)
	// Claims one context but truncates it.
	short := dcerpcFrame(dcerpcPTypeBind, 1, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0})
	_, ok = ParseBind(short)
	require.False(t, ok)
}

func TestBuildBindAck(t *testing.T) {
	ctxs, _ := ParseBind(buildBindPDU(0x2a))
	ack := BuildBindAck(0x2a, `\PIPE\srvsvc`, ctxs)
	h, ok := ParseDCERPCHeader(ack)
	require.True(t, ok)
	require.Equal(t, byte(dcerpcPTypeBindAck), h.PType)
	require.Equal(t, uint32(0x2a), h.CallID)
	require.Equal(t, uint16(len(ack)), h.FragLen)
	require.Equal(t, "DCERPC_BIND_ACK", DCERPCName(h.PType))
}

func TestParseRequest(t *testing.T) {
	stub := []byte("payload-args")
	body := []byte{0x10, 0x00, 0x00, 0x00} // alloc_hint
	body = append(body, 0x00, 0x00)        // p_cont_id
	body = append(body, 0x0f, 0x00)        // opnum 15 (OpenSCManagerW)
	body = append(body, stub...)
	pdu := dcerpcFrame(dcerpcPTypeRequest, 7, body)

	opnum, ctxID, got, ok := ParseRequest(pdu)
	require.True(t, ok)
	require.Equal(t, uint16(15), opnum)
	require.Equal(t, uint16(0), ctxID)
	require.Equal(t, stub, got)
}

func TestBuildFault(t *testing.T) {
	f := BuildFault(7)
	h, ok := ParseDCERPCHeader(f)
	require.True(t, ok)
	require.Equal(t, byte(dcerpcPTypeFault), h.PType)
	require.Equal(t, uint32(7), h.CallID)
	require.Equal(t, uint32(dcerpcFaultNDR), binary.LittleEndian.Uint32(f[dcerpcHeaderLen+8:dcerpcHeaderLen+12]))
}

func TestParseDCERPCHeaderRejectsBadVersion(t *testing.T) {
	_, ok := ParseDCERPCHeader([]byte{0x04, 0x00, 0x0b, 0x03, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	require.False(t, ok)
}
