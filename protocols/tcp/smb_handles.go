package tcp

import (
	"github.com/mushorg/glutton/protocols/tcp/smb"
)

// smbHandle is an open NT Create AndX file or named pipe.
type smbHandle struct {
	name      string
	isPipe    bool
	createEvt int    // index of the NT Create read frame
	fileBuf   []byte // captured file-write bytes (non-pipe)
	rpcIn     []byte // buffered inbound DCERPC
	rpcOut    []byte // pending DCERPC reply, served on the next READ_ANDX
	iface     string // bound interface UUID
	ifaceVer  string
}

// captureFile appends file-write bytes to an open disk-file handle, bounded.
func (hn *smbHandle) captureFile(data []byte) {
	if hn.isPipe || len(data) == 0 {
		return
	}
	if room := maxSMBFileBuffer - len(hn.fileBuf); room > 0 {
		hn.fileBuf = append(hn.fileBuf, data[:min(len(data), room)]...)
	}
}

// closeHandle stores a captured upload and tags its NT Create read frame.
func (ss *smbServer) closeHandle(fid uint16) {
	hn := ss.handles[fid]
	if hn == nil {
		return
	}
	delete(ss.handles, fid)
	if hn.isPipe || len(hn.fileBuf) == 0 {
		return
	}
	hash, ok := ss.storePayload(hn.fileBuf, "SMB upload")
	if !ok {
		return
	}
	if ev := ss.event(hn.createEvt); ev != nil {
		ev.PayloadHash = hash
	}
}

// feedPipe buffers DCERPC data written to a named pipe, and when a full
// fragment has arrived accepts a bind or faults a request. It never emulates an
// RPC service: binds are acknowledged and requests are logged then faulted
// (srvsvc NetrShareEnum alone is answered from a fake share table), so
// the honeypot captures which interface and operation were called (and the
// request stub) without acting as a working backend. The reply is queued on
// hn.rpcOut for the next READ_ANDX. readIdx is the WRITE_ANDX read frame to
// annotate.
func (ss *smbServer) feedPipe(hn *smbHandle, data []byte, readIdx int) {
	if len(data) == 0 {
		return
	}
	hn.rpcIn = append(hn.rpcIn, data...)
	hdr, ok := smb.ParseDCERPCHeader(hn.rpcIn)
	if !ok {
		if len(hn.rpcIn) >= 16 {
			hn.rpcIn = nil // not DCERPC: drop it (the frame payload keeps the bytes)
		}
		return
	}
	if len(hn.rpcIn) < int(hdr.FragLen) || hdr.FragLen < 16 {
		return // wait for the rest of the fragment
	}
	pdu := hn.rpcIn[:hdr.FragLen]
	hn.rpcIn = hn.rpcIn[hdr.FragLen:]

	// Annotations go to a scratch frame when readIdx is out of range, so the
	// reply logic below does not need to check.
	ev := ss.event(readIdx)
	if ev == nil {
		ev = &parsedSMB{}
	}
	ev.DCERPC = smb.DCERPCName(hdr.PType)
	switch hdr.PType {
	case smb.PTypeBind:
		ss.pipeBind(hn, hdr, pdu, ev)
	case smb.PTypeRequest:
		ss.pipeRequest(hn, hdr, pdu, ev)
	}
}

// pipeBind binds the first presented interface and queues a bind_ack.
func (ss *smbServer) pipeBind(hn *smbHandle, hdr smb.DCERPCHeader, pdu []byte, ev *parsedSMB) {
	ctxs, ok := smb.ParseBind(pdu)
	if !ok {
		return
	}
	hn.iface = ctxs[0].InterfaceUUID()
	hn.ifaceVer = ctxs[0].InterfaceVersion()
	ev.Interface = hn.iface
	ev.InterfaceVer = hn.ifaceVer
	hn.rpcOut = smb.BuildBindAck(hdr.CallID, `\PIPE`+hn.name, ctxs)
}

// pipeRequest records the called operation, stores its stub, and queues a
// fault (or a fake share list for srvsvc NetrShareEnum).
func (ss *smbServer) pipeRequest(hn *smbHandle, hdr smb.DCERPCHeader, pdu []byte, ev *parsedSMB) {
	opnum, ctxID, stub, ok := smb.ParseRequest(pdu)
	if !ok {
		return
	}
	ev.Opnum = &opnum
	ev.Interface = hn.iface
	ev.InterfaceVer = hn.ifaceVer
	if len(stub) > 0 {
		if hash, ok := ss.storePayload(stub, "DCERPC stub"); ok {
			ev.PayloadHash = hash
		}
	}
	hn.rpcOut = smb.BuildFault(hdr.CallID)
	if hn.iface == smb.SrvsvcUUID && opnum == smb.SrvsvcOpNetrShareEnum {
		if level, ok := smb.ParseNetShareEnumLevel(stub); ok {
			if resp, ok := smb.BuildNetShareEnumResponse(hdr.CallID, ctxID, level, smb.Shares); ok {
				hn.rpcOut = resp
			}
		}
	}
}
