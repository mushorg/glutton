package tcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/tcp/smb"
)

const (
	maxSMBMessage    = 256 * 1024
	maxSMBMessages   = 128
	maxSMBClaimedLen = 16 * 1024 * 1024
	maxSMBTxBuffer   = 4 * 1024 * 1024
)

var smbStore = helpers.Store

type parsedSMB struct {
	Direction      string        `json:"direction,omitempty"`
	Header         smb.SMBHeader `json:"header,omitempty"`
	Command        string        `json:"command,omitempty"`
	Path           string        `json:"path,omitempty"`
	Setup          string        `json:"setup,omitempty"`
	Status         string        `json:"status,omitempty"`
	NTStatus       uint32        `json:"nt_status,omitempty"`
	Account        string        `json:"account,omitempty"`
	NativeOS       string        `json:"native_os,omitempty"`
	NativeLanMan   string        `json:"native_lanman,omitempty"`
	Domain         string        `json:"domain,omitempty"`
	Workstation    string        `json:"workstation,omitempty"`
	CalledName     string        `json:"called_name,omitempty"`
	CallingName    string        `json:"calling_name,omitempty"`
	DCERPC         string        `json:"dcerpc,omitempty"`
	Interface      string        `json:"interface,omitempty"`
	InterfaceVer   string        `json:"interface_version,omitempty"`
	Opnum          *uint16       `json:"opnum,omitempty"`
	TotalDataCount uint32        `json:"total_data_count,omitempty"`
	PayloadHash    string        `json:"payload_hash,omitempty"`
	Payload        []byte        `json:"payload,omitempty"`
	Truncated      bool          `json:"truncated,omitempty"`
}

var smbReadRand = rand.Read

type smbServer struct {
	events       []parsedSMB
	conn         net.Conn
	uid          uint16
	tid          uint16
	fid          uint16
	txTotal      uint32
	txOpen       bool
	txBuf        []byte
	txEvent      int
	tidIsIPC     map[uint16]bool
	handles      map[uint16]*smbHandle
	challenge    [8]byte
	challengeSet bool
}

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

var maxSMBFileBuffer = 8 * 1024 * 1024

func (ss *smbServer) ensureChallenge() {
	if !ss.challengeSet {
		_, _ = smbReadRand(ss.challenge[:])
		ss.challengeSet = true
	}
}

// sessionUID reuses the UID the client echoes back (NTLM step 2) or assigns a
// fresh one on the first Session Setup.
func (ss *smbServer) sessionUID(header smb.SMBHeader) uint16 {
	if uid := binary.LittleEndian.Uint16(header.UID[:]); uid != 0 {
		return uid
	}
	return ss.nextUID()
}

type smbFrame struct {
	payload   []byte
	truncated bool
}

func (ss *smbServer) read() (smbFrame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(ss.conn, hdr[:]); err != nil {
		return smbFrame{}, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	// Only NBSS control packets (keepalive) may be empty.
	if n > maxSMBClaimedLen || (n == 0 && hdr[0] == smb.NBSSSessionMessage) {
		return smbFrame{}, fmt.Errorf("invalid SMB message length: %d", n)
	}
	store := n
	truncated := false
	if store > maxSMBMessage {
		store = maxSMBMessage
		truncated = true
	}
	body := make([]byte, store)
	if _, err := io.ReadFull(ss.conn, body); err != nil {
		return smbFrame{}, err
	}
	if truncated {
		if _, err := io.CopyN(io.Discard, ss.conn, int64(n-store)); err != nil {
			return smbFrame{}, err
		}
	}
	payload := make([]byte, 4+store)
	copy(payload[:4], hdr[:])
	copy(payload[4:], body)
	return smbFrame{payload: payload, truncated: truncated}, nil
}

func (ss *smbServer) write(header smb.SMBHeader, data []byte) error {
	return ss.writePDU(smb.CommandName(header.Command), header, data)
}

func (ss *smbServer) writePDU(command string, header smb.SMBHeader, data []byte) error {
	framed := smb.WrapSessionMessage(data)
	if _, err := ss.conn.Write(framed); err != nil {
		return err
	}
	ss.events = append(ss.events, parsedSMB{
		Direction: "write",
		Header:    header,
		Command:   command,
		Status:    smb.StatusName(header),
		NTStatus:  smb.NTStatus(header),
		Payload:   framed,
	})
	return nil
}

func (ss *smbServer) nextUID() uint16 {
	ss.uid++
	return ss.uid
}

func (ss *smbServer) nextTID() uint16 {
	ss.tid++
	return ss.tid
}

func (ss *smbServer) nextFID() uint16 {
	ss.fid++
	return ss.fid
}

// flushTx stores the reassembled transaction data and tags the NT_TRANSACT
// read frame that started it with the content hash.
func (ss *smbServer) flushTx(logger interfaces.Logger) {
	buf := ss.txBuf
	ss.txBuf = nil
	if len(buf) == 0 {
		return
	}
	hash := helpers.SHA256Hex(buf)
	if _, err := smbStore(buf, filepath.Join("payloads", "smb")); err != nil {
		logger.Error("Failed to store SMB transaction payload", slog.String("protocol", "smb"), producer.ErrAttr(err))
		return
	}
	if ss.txEvent < len(ss.events) {
		ss.events[ss.txEvent].PayloadHash = hash
	}
}

// writeNBSS sends a NetBIOS session control packet (already framed).
func (ss *smbServer) writeNBSS(data []byte) error {
	if _, err := ss.conn.Write(data); err != nil {
		return err
	}
	ss.events = append(ss.events, parsedSMB{
		Direction: "write",
		Command:   smb.NBSSTypeName(data[0]),
		Payload:   data,
	})
	return nil
}

// handleNBSS records a NetBIOS session control packet (port 139 framing) and
// accepts session requests so the client continues with SMB Negotiate.
func (ss *smbServer) handleNBSS(frame smbFrame) error {
	ev := parsedSMB{
		Direction: "read",
		Command:   smb.NBSSTypeName(frame.payload[0]),
		Payload:   frame.payload,
		Truncated: frame.truncated,
	}
	if frame.payload[0] != smb.NBSSSessionRequest {
		ss.events = append(ss.events, ev)
		return nil
	}
	ev.CalledName, ev.CallingName, _ = smb.ParseSessionRequest(smbPDU(frame))
	ss.events = append(ss.events, ev)
	return ss.writeNBSS(smb.MakePositiveSessionResponse())
}

func smbPDU(frame smbFrame) []byte {
	if len(frame.payload) <= 4 {
		return nil
	}
	return frame.payload[4:]
}

// feedPipe buffers DCERPC data written to a named pipe, and when a full
// fragment has arrived accepts a bind or faults a request. It never emulates an
// RPC service: binds are acknowledged and requests are logged then faulted, so
// the honeypot captures which interface and operation were called (and the
// request stub) without acting as a working backend. readIdx is the WRITE_ANDX
// read frame to annotate.
func (ss *smbServer) feedPipe(hn *smbHandle, data []byte, readIdx int, logger interfaces.Logger) {
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

	if readIdx >= 0 && readIdx < len(ss.events) {
		ss.events[readIdx].DCERPC = smb.DCERPCName(hdr.PType)
	}
	switch hdr.PType {
	case smb.PTypeBind:
		ctxs, ok := smb.ParseBind(pdu)
		if !ok {
			return
		}
		hn.iface = ctxs[0].InterfaceUUID()
		hn.ifaceVer = ctxs[0].InterfaceVersion()
		if readIdx >= 0 && readIdx < len(ss.events) {
			ss.events[readIdx].Interface = hn.iface
			ss.events[readIdx].InterfaceVer = hn.ifaceVer
		}
		hn.rpcOut = smb.BuildBindAck(hdr.CallID, `\PIPE`+hn.name, ctxs)
	case smb.PTypeRequest:
		opnum, _, stub, ok := smb.ParseRequest(pdu)
		if !ok {
			return
		}
		if readIdx >= 0 && readIdx < len(ss.events) {
			op := opnum
			ss.events[readIdx].Opnum = &op
			ss.events[readIdx].Interface = hn.iface
			ss.events[readIdx].InterfaceVer = hn.ifaceVer
			if len(stub) > 0 {
				if hash, err := smbStore(stub, filepath.Join("payloads", "smb")); err != nil {
					logger.Error("Failed to store DCERPC stub", slog.String("protocol", "smb"), producer.ErrAttr(err))
				} else {
					ss.events[readIdx].PayloadHash = hash
				}
			}
		}
		hn.rpcOut = smb.BuildFault(hdr.CallID)
	}
}

// captureFile appends file-write bytes to an open disk-file handle, bounded.
func (hn *smbHandle) captureFile(data []byte) {
	if hn.isPipe || len(data) == 0 {
		return
	}
	if room := maxSMBFileBuffer - len(hn.fileBuf); room > 0 {
		if len(data) > room {
			data = data[:room]
		}
		hn.fileBuf = append(hn.fileBuf, data...)
	}
}

// closeHandle stores a captured upload and tags its NT Create read frame.
func (ss *smbServer) closeHandle(fid uint16, logger interfaces.Logger) {
	hn := ss.handles[fid]
	if hn == nil {
		return
	}
	delete(ss.handles, fid)
	if hn.isPipe || len(hn.fileBuf) == 0 {
		return
	}
	hash, err := smbStore(hn.fileBuf, filepath.Join("payloads", "smb"))
	if err != nil {
		logger.Error("Failed to store SMB upload", slog.String("protocol", "smb"), producer.ErrAttr(err))
		return
	}
	if hn.createEvt >= 0 && hn.createEvt < len(ss.events) {
		ss.events[hn.createEvt].PayloadHash = hash
	}
}

// smbTargetName is the NTLM/SPNEGO target name advertised in challenges; it
// matches the NetBIOS server name used elsewhere.
const smbTargetName = "SERVER"

// sessionSetup answers an SMB1 Session Setup AndX. Extended-security requests
// (WordCount 12) drive the NTLMSSP challenge/accept exchange and record the
// authenticating identity; basic requests get the plain response.
func (ss *smbServer) sessionSetup(header smb.SMBHeader, body []byte, readIdx int) (smb.SMBHeader, []byte, error) {
	var wc byte
	if len(body) > 0 {
		wc = body[0]
	}
	if wc != 12 {
		return smb.MakeSessionSetupAndXResponse(header, ss.nextUID())
	}
	ntlm, ok := smb.FindNTLMSSP(body)
	if !ok {
		// Extended security without NTLMSSP (e.g. Kerberos): accept.
		return smb.MakeSessionSetupESecResponse(header, ss.sessionUID(header), smb.SPNEGOAccept(), false)
	}
	switch smb.NTLMMessageType(ntlm) {
	case 1:
		ss.ensureChallenge()
		blob := smb.SPNEGOChallenge(smb.BuildChallenge(ss.challenge, smbTargetName))
		return smb.MakeSessionSetupESecResponse(header, ss.sessionUID(header), blob, true)
	case 3:
		ss.recordNTLMIdentity(smb.ParseAuthenticate(ntlm), readIdx)
		return smb.MakeSessionSetupESecResponse(header, ss.sessionUID(header), smb.SPNEGOAccept(), false)
	default:
		return smb.MakeSessionSetupESecResponse(header, ss.sessionUID(header), smb.SPNEGOAccept(), false)
	}
}

// recordNTLMIdentity sets the non-secret identity fields on a read frame. The
// NTLM response hashes are never recorded.
func (ss *smbServer) recordNTLMIdentity(id smb.NTLMIdentity, readIdx int) {
	if readIdx < 0 || readIdx >= len(ss.events) {
		return
	}
	if id.User != "" {
		ss.events[readIdx].Account = id.User
	}
	ss.events[readIdx].Domain = id.Domain
	ss.events[readIdx].Workstation = id.Workstation
}

// HandleSMB takes a net.Conn and does basic SMB communication
func HandleSMB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &smbServer{
		events:   []parsedSMB{},
		conn:     conn,
		tidIsIPC: map[uint16]bool{},
		handles:  map[uint16]*smbHandle{},
	}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		server.flushTx(logger)
		if err := h.ProduceTCP("smb", conn, md, helpers.FirstOrEmpty[parsedSMB](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "smb"), producer.ErrAttr(err))
		}

		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SMB connection", producer.ErrAttr(err), slog.String("protocol", "smb"))
		}
	}()

	i := 0
	for ; i < maxSMBMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "smb"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		frame, err := server.read()
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "smb"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			break
		}
		pdu := smbPDU(frame)

		switch {
		case frame.payload[0] != smb.NBSSSessionMessage:
			if err := server.handleNBSS(frame); err != nil {
				endReason = connection.EndWriteError
				return err
			}
		case bytes.HasPrefix(pdu, []byte("\xffSMB")):
			if err := server.handleSMB1(frame, pdu, logger); err != nil {
				endReason = connection.EndWriteError
				return err
			}
		case bytes.HasPrefix(pdu, []byte("\xfeSMB")):
			if err := server.handleSMB2(frame, pdu); err != nil {
				endReason = connection.EndWriteError
				return err
			}
		case bytes.HasPrefix(pdu, []byte("\xfdSMB")):
			server.events = append(server.events, parsedSMB{
				Direction: "read",
				Command:   "SMB3_TRANSFORM",
				Payload:   frame.payload,
				Truncated: frame.truncated,
			})
		default:
			server.events = append(server.events, parsedSMB{
				Direction: "read",
				Payload:   frame.payload,
				Truncated: frame.truncated,
			})
		}
	}
	if i >= maxSMBMessages {
		endReason = connection.EndMaxFrames
	}
	return nil
}

func (ss *smbServer) handleSMB1(frame smbFrame, pdu []byte, logger interfaces.Logger) error {
	smbBuf := bytes.NewBuffer(pdu)
	header := smb.SMBHeader{}
	if err := smb.ParseHeader(smbBuf, &header); err != nil {
		ss.events = append(ss.events, parsedSMB{
			Direction: "read",
			Payload:   frame.payload,
			Truncated: frame.truncated,
		})
		logger.Debug("Failed to parse SMB header", slog.String("protocol", "smb"), producer.ErrAttr(err))
		return nil
	}

	path := ""
	setup := ""
	account, nativeOS, nativeLanMan := "", "", ""
	var totalDataCount uint32
	switch header.Command {
	case smb.CmdNtCreateAndX:
		path = smb.NtCreateAndXName(header, smbBuf.Bytes())
	case smb.CmdTreeConnectAndX:
		path = smb.TreeConnectShare(header, smbBuf.Bytes())
	case smb.CmdSessionSetupAndX:
		id := smb.SessionSetupIdentity(header, smbBuf.Bytes())
		account, nativeOS, nativeLanMan = id.Account, id.NativeOS, id.NativeLanMan
	case smb.CmdTransaction2:
		if s, ok := smb.Trans2Setup(smbBuf.Bytes()); ok {
			setup = smb.Trans2SetupName(s)
		}
	case smb.CmdNtTransact:
		totalDataCount = smb.NtTransactTotalDataCount(smbBuf.Bytes())
	}
	ss.events = append(ss.events, parsedSMB{
		Direction:      "read",
		Header:         header,
		Command:        smb.CommandName(header.Command),
		Path:           path,
		Setup:          setup,
		Account:        account,
		NativeOS:       nativeOS,
		NativeLanMan:   nativeLanMan,
		TotalDataCount: totalDataCount,
		Payload:        frame.payload,
		Truncated:      frame.truncated,
	})
	logger.Debug("SMB Header", slog.Any("header", header), slog.String("protocol", "smb"))
	readIdx := len(ss.events) - 1
	body := smbBuf.Bytes()

	var (
		responseHeader smb.SMBHeader
		resp           []byte
		err            error
	)
	switch header.Command {
	case smb.CmdNegotiate:
		var dialects []byte
		if req, err := smb.ParseNegotiateProtocolRequest(smbBuf, header); err == nil {
			dialects = req.Data.DialectString
		}
		responseHeader, resp, err = smb.MakeNegotiateProtocolResponse(header, dialects)
	case smb.CmdSessionSetupAndX:
		responseHeader, resp, err = ss.sessionSetup(header, body, readIdx)
	case smb.CmdTreeConnectAndX:
		share := smb.TreeConnectShare(header, body)
		if smb.IsProbeShare(share) {
			responseHeader, resp, err = smb.MakeBadNetworkNameResponse(header)
		} else {
			tid := ss.nextTID()
			ss.tidIsIPC[tid] = smb.IsIPCShare(share)
			responseHeader, resp, err = smb.MakeTreeConnectAndXResponse(header, tid, share)
		}
	case smb.CmdNtCreateAndX:
		tid := binary.LittleEndian.Uint16(header.TID[:])
		isPipe := ss.tidIsIPC[tid]
		fid := ss.nextFID()
		ss.handles[fid] = &smbHandle{name: path, isPipe: isPipe, createEvt: readIdx}
		responseHeader, resp, err = smb.MakeNtCreateAndXResponse(header, fid, isPipe)
	case smb.CmdTreeDisconnect, smb.CmdLogoffAndX:
		responseHeader, resp, err = smb.MakeHeaderResponse(header)
	case smb.CmdTransaction2:
		setup, setupOK := smb.Trans2Setup(smbBuf.Bytes())
		responseHeader, resp, err = smb.MakeComTransaction2Reply(header, setup, setupOK)
	case smb.CmdTransaction:
		responseHeader, resp, err = smb.MakeComTransactionResponse(header)
	case smb.CmdNtTransact:
		responseHeader, resp, err = smb.MakeComNtTransactionResponse(header)
		ss.flushTx(logger)
		ss.txTotal = totalDataCount
		ss.txOpen = totalDataCount > 0
		ss.txEvent = len(ss.events) - 1
		if ss.txOpen && totalDataCount <= maxSMBTxBuffer && !frame.truncated {
			ss.txBuf = make([]byte, totalDataCount)
			copy(ss.txBuf, smb.NtTransactData(pdu))
		}
	case smb.CmdNtTransactSecondary, smb.CmdTransactionSecondary, smb.CmdTransaction2Secondary:
		disp, count, ok := smb.SecondaryDataRange(header.Command, smbBuf.Bytes())
		if ss.txOpen && ss.txBuf != nil && !frame.truncated {
			if d, data, dok := smb.SecondaryData(header.Command, pdu); dok && uint64(d)+uint64(len(data)) <= uint64(len(ss.txBuf)) {
				copy(ss.txBuf[d:], data)
			}
		}
		if !ss.txOpen || !ok || uint64(disp)+uint64(count) < uint64(ss.txTotal) {
			return nil // middle fragment: no reply
		}
		ss.txOpen = false
		ss.flushTx(logger)
		responseHeader, resp, err = smb.MakeTransactionCompleteResponse(header)
	case smb.CmdWriteAndX:
		fid := smb.WriteAndXFID(body)
		data := smb.WriteAndXData(pdu)
		if hn := ss.handles[fid]; hn != nil {
			if hn.isPipe {
				ss.feedPipe(hn, data, readIdx, logger)
			} else {
				hn.captureFile(data)
			}
		}
		count := smb.WriteAndXDataLength(body)
		responseHeader, resp, err = smb.MakeWriteAndXResponse(header, count)
	case smb.CmdWrite:
		data := smb.WriteData(pdu)
		if hn := ss.handles[smb.WriteFID(body)]; hn != nil && !hn.isPipe {
			hn.captureFile(data)
		}
		responseHeader, resp, err = smb.MakeWriteResponse(header, uint16(len(data)))
	case smb.CmdReadAndX:
		fid := smb.ReadAndXFID(body)
		if hn := ss.handles[fid]; hn != nil && hn.isPipe && len(hn.rpcOut) > 0 {
			out := hn.rpcOut
			hn.rpcOut = nil
			responseHeader, resp, err = smb.MakeReadAndXDataResponse(header, out)
		} else {
			responseHeader, resp, err = smb.MakeReadAndXResponse(header)
		}
	case smb.CmdClose:
		ss.closeHandle(smb.CloseFID(body), logger)
		responseHeader, resp, err = smb.MakeHeaderResponse(header)
	case smb.CmdEcho:
		responseHeader, resp, err = smb.MakeEchoResponse(header, body)
	default:
		responseHeader, resp, err = smb.MakeHeaderResponse(header)
	}
	if err != nil {
		return err
	}
	return ss.write(responseHeader, resp)
}

func (ss *smbServer) handleSMB2(frame smbFrame, pdu []byte) error {
	ss.ensureChallenge()
	name, resp, ok := smb.MakeSMB2Reply(pdu, ss.challenge)
	if name == "" {
		name = "SMB2"
	}
	ss.events = append(ss.events, parsedSMB{
		Direction: "read",
		Command:   name,
		Payload:   frame.payload,
		Truncated: frame.truncated,
	})
	// Record the identity from an SMB2 NTLMSSP AUTHENTICATE (no secrets).
	if ntlm, found := smb.FindNTLMSSP(pdu); found && smb.NTLMMessageType(ntlm) == 3 {
		ss.recordNTLMIdentity(smb.ParseAuthenticate(ntlm), len(ss.events)-1)
	}
	if !ok {
		return nil
	}
	return ss.writePDU(name, smb.SMBHeader{}, resp)
}
