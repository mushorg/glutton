package smb

import (
	"bytes"
	"encoding/binary"
	"log/slog"

	"github.com/mushorg/glutton/producer"
)

// smb1Request is one parsed SMB1 message.
type smb1Request struct {
	frame   Frame
	header  SMBHeader
	pdu     []byte // SMB message including its 32-byte header
	body    []byte // everything after the header (WordCount onwards)
	readIdx int    // index of the read frame recorded for this request
}

// read is the frame recorded for this request.
func (req *smb1Request) read(ss *Server) *Event {
	return ss.event(req.readIdx)
}

// smb1Handler answers one SMB1 command. It is responsible for writing the
// reply (usually via reply/replyDP) or deliberately sending none.
type smb1Handler func(ss *Server, req *smb1Request) error

// smb1Handlers maps an SMB1 command code to its handler. Commands not listed
// get a bare success header (Server.replyHeaderOnly). To support a new
// command, add parsing/response code to protocols/tcp/smb, annotate the read
// frame in describeSMB1 if it carries something worth logging, and register a
// handler here.
var smb1Handlers = map[byte]smb1Handler{
	CmdNegotiate:             (*Server).negotiate,
	CmdSessionSetupAndX:      (*Server).sessionSetup,
	CmdTreeConnectAndX:       (*Server).treeConnect,
	CmdNtCreateAndX:          (*Server).ntCreate,
	CmdTransaction:           (*Server).transaction,
	CmdTransaction2:          (*Server).transaction2,
	CmdNtTransact:            (*Server).ntTransact,
	CmdTransactionSecondary:  (*Server).transactionSecondary,
	CmdTransaction2Secondary: (*Server).transactionSecondary,
	CmdNtTransactSecondary:   (*Server).transactionSecondary,
	CmdWriteAndX:             (*Server).writeAndX,
	CmdWrite:                 (*Server).writeCmd,
	CmdReadAndX:              (*Server).readAndX,
	CmdClose:                 (*Server).closeCmd,
	CmdEcho:                  (*Server).echo,
}

func (ss *Server) handleSMB1(frame Frame) error {
	pdu := frame.pdu()
	smbBuf := bytes.NewBuffer(pdu)
	header := SMBHeader{}
	if err := ParseHeader(smbBuf, &header); err != nil {
		ss.recordRead(frame, Event{})
		ss.logger.Debug("Failed to parse SMB header", slog.String("protocol", "smb"), producer.ErrAttr(err))
		return nil
	}
	req := &smb1Request{frame: frame, header: header, pdu: pdu, body: smbBuf.Bytes()}
	req.readIdx = ss.recordRead(frame, describeSMB1(header, req.body))
	ss.logger.Debug("SMB Header", slog.Any("header", header), slog.String("protocol", "smb"))

	handle, ok := smb1Handlers[header.Command]
	if !ok {
		handle = (*Server).replyHeaderOnly
	}
	return handle(ss, req)
}

// describeSMB1 extracts the request fields logged on the read frame. It only
// parses; session state is updated by the command handlers.
func describeSMB1(header SMBHeader, body []byte) Event {
	ev := Event{
		Header:  header,
		Command: CommandName(header.Command),
	}
	switch header.Command {
	case CmdNtCreateAndX:
		ev.Path = NtCreateAndXName(header, body)
	case CmdTreeConnectAndX:
		ev.Path = TreeConnectShare(header, body)
	case CmdSessionSetupAndX:
		id := SessionSetupIdentity(header, body)
		ev.Account = id.Account
		ev.Password = id.Password
		ev.LMResponse = id.LMResponse
		ev.NTLMResponse = id.NTLMResponse
		ev.NativeOS = id.NativeOS
		ev.NativeLanMan = id.NativeLanMan
	case CmdTransaction2:
		if s, ok := Trans2Setup(body); ok {
			ev.Setup = Trans2SetupName(s)
			if s == Trans2SessionSetup {
				ev.TotalDataCount = Trans2TotalDataCount(body)
			}
		}
	case CmdNtTransact:
		ev.TotalDataCount = NtTransactTotalDataCount(body)
	}
	return ev
}

// reply writes a response built by one of the Make* functions.
func (ss *Server) reply(header SMBHeader, resp []byte, err error) error {
	if err != nil {
		return err
	}
	return ss.write(header, resp)
}

func (ss *Server) replyHeaderOnly(req *smb1Request) error {
	return ss.reply(MakeHeaderResponse(req.header))
}

func (ss *Server) negotiate(req *smb1Request) error {
	var dialects []byte
	if parsed, err := ParseNegotiateProtocolRequest(bytes.NewBuffer(req.body), req.header); err == nil {
		dialects = parsed.Data.DialectString
	}
	return ss.reply(MakeNegotiateProtocolResponse(req.header, dialects))
}

// sessionSetup answers an SMB1 Server Setup AndX. Extended-security requests
// (WordCount 12) drive the NTLMSSP challenge/accept exchange and record the
// authenticating identity; basic requests get the plain response.
func (ss *Server) sessionSetup(req *smb1Request) error {
	header := req.header
	if len(req.body) == 0 || req.body[0] != 12 {
		return ss.reply(MakeSessionSetupAndXResponse(header, ss.nextUID()))
	}
	accept := func() error {
		return ss.reply(MakeSessionSetupESecResponse(header, ss.sessionUID(header), SPNEGOAccept(), false))
	}
	ntlm, ok := FindNTLMSSP(req.body)
	if !ok {
		// Extended security without NTLMSSP (e.g. Kerberos): accept.
		return accept()
	}
	switch NTLMMessageType(ntlm) {
	case 1:
		ss.ensureChallenge()
		blob := SPNEGOChallenge(BuildChallenge(ss.challenge, serverName))
		return ss.reply(MakeSessionSetupESecResponse(header, ss.sessionUID(header), blob, true))
	case 3:
		ss.recordNTLMIdentity(ParseAuthenticate(ntlm), req.readIdx)
	}
	return accept()
}

func (ss *Server) treeConnect(req *smb1Request) error {
	share := req.read(ss).Path
	if IsProbeShare(share) {
		return ss.reply(MakeBadNetworkNameResponse(req.header))
	}
	tid := ss.nextTID()
	ss.tidIsIPC[tid] = IsIPCShare(share)
	return ss.reply(MakeTreeConnectAndXResponse(req.header, tid, share))
}

// ntCreate opens a handle: a named pipe on an IPC$ tree, a disk file
// otherwise.
func (ss *Server) ntCreate(req *smb1Request) error {
	tid := binary.LittleEndian.Uint16(req.header.TID[:])
	isPipe := ss.tidIsIPC[tid]
	fid := ss.nextFID()
	ss.handles[fid] = &fileHandle{name: req.read(ss).Path, isPipe: isPipe, createEvt: req.readIdx}
	return ss.reply(MakeNtCreateAndXResponse(req.header, fid, isPipe))
}

func (ss *Server) writeAndX(req *smb1Request) error {
	data := WriteAndXData(req.pdu)
	if hn := ss.handles[WriteAndXFID(req.body)]; hn != nil {
		if hn.isPipe {
			ss.feedPipe(hn, data, req.readIdx)
		} else {
			hn.captureFile(data, ss.maxFileBuffer)
		}
	}
	return ss.reply(MakeWriteAndXResponse(req.header, WriteAndXDataLength(req.body)))
}

func (ss *Server) writeCmd(req *smb1Request) error {
	data := WriteData(req.pdu)
	if hn := ss.handles[WriteFID(req.body)]; hn != nil && !hn.isPipe {
		hn.captureFile(data, ss.maxFileBuffer)
	}
	return ss.reply(MakeWriteResponse(req.header, uint16(len(data))))
}

// readAndX serves a pending DCERPC reply from a named pipe, or no data.
func (ss *Server) readAndX(req *smb1Request) error {
	if hn := ss.handles[ReadAndXFID(req.body)]; hn != nil && hn.isPipe && len(hn.rpcOut) > 0 {
		out := hn.rpcOut
		hn.rpcOut = nil
		return ss.reply(MakeReadAndXDataResponse(req.header, out))
	}
	return ss.reply(MakeReadAndXResponse(req.header))
}

func (ss *Server) closeCmd(req *smb1Request) error {
	ss.closeHandle(CloseFID(req.body))
	return ss.replyHeaderOnly(req)
}

func (ss *Server) echo(req *smb1Request) error {
	return ss.reply(MakeEchoResponse(req.header, req.body))
}
