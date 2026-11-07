package smb

// fileHandle is an open NT Create AndX file or named pipe.
type fileHandle struct {
	name      string
	isPipe    bool
	createEvt int    // index of the NT Create read frame
	fileBuf   []byte // captured file-write bytes (non-pipe)
	rpcIn     []byte // buffered inbound DCERPC
	rpcOut    []byte // pending DCERPC reply, served on the next READ_ANDX
	iface     string // bound interface UUID
	ifaceVer  string
}

// captureFile appends file-write bytes to an open disk-file handle, keeping at
// most limit bytes.
func (hn *fileHandle) captureFile(data []byte, limit int) {
	if hn.isPipe || len(data) == 0 {
		return
	}
	if room := limit - len(hn.fileBuf); room > 0 {
		hn.fileBuf = append(hn.fileBuf, data[:min(len(data), room)]...)
	}
}

// closeHandle stores a captured upload and tags its NT Create read frame.
func (ss *Server) closeHandle(fid uint16) {
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
func (ss *Server) feedPipe(hn *fileHandle, data []byte, readIdx int) {
	if len(data) == 0 {
		return
	}
	hn.rpcIn = append(hn.rpcIn, data...)
	hdr, ok := ParseDCERPCHeader(hn.rpcIn)
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
		ev = &Event{}
	}
	ev.DCERPC = DCERPCName(hdr.PType)
	switch hdr.PType {
	case PTypeBind:
		ss.pipeBind(hn, hdr, pdu, ev)
	case PTypeRequest:
		ss.pipeRequest(hn, hdr, pdu, ev)
	}
}

// pipeBind binds the first presented interface and queues a bind_ack.
func (ss *Server) pipeBind(hn *fileHandle, hdr DCERPCHeader, pdu []byte, ev *Event) {
	ctxs, ok := ParseBind(pdu)
	if !ok {
		return
	}
	hn.iface = ctxs[0].InterfaceUUID()
	hn.ifaceVer = ctxs[0].InterfaceVersion()
	ev.Interface = hn.iface
	ev.InterfaceVer = hn.ifaceVer
	hn.rpcOut = BuildBindAck(hdr.CallID, `\PIPE`+hn.name, ctxs)
}

// pipeRequest records the called operation, stores its stub, and queues a
// fault (or a fake share list for srvsvc NetrShareEnum).
func (ss *Server) pipeRequest(hn *fileHandle, hdr DCERPCHeader, pdu []byte, ev *Event) {
	opnum, ctxID, stub, ok := ParseRequest(pdu)
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
	hn.rpcOut = BuildFault(hdr.CallID)
	if hn.iface == SrvsvcUUID && opnum == SrvsvcOpNetrShareEnum {
		if level, ok := ParseNetShareEnumLevel(stub); ok {
			if resp, ok := BuildNetShareEnumResponse(hdr.CallID, ctxID, level, Shares); ok {
				hn.rpcOut = resp
			}
		}
	}
}
