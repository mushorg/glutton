package tcp

import (
	"bytes"
	"encoding/binary"
	"log/slog"

	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/tcp/smb"
)

// smbTargetName is the NTLM/SPNEGO target name advertised in challenges; it
// matches the NetBIOS server name used elsewhere.
const smbTargetName = "SERVER"

// smb1Request is one parsed SMB1 message.
type smb1Request struct {
	frame   smbFrame
	header  smb.SMBHeader
	pdu     []byte // SMB message including its 32-byte header
	body    []byte // everything after the header (WordCount onwards)
	readIdx int    // index of the read frame recorded for this request
}

// read is the frame recorded for this request.
func (req *smb1Request) read(ss *smbServer) *parsedSMB {
	return ss.event(req.readIdx)
}

// smb1Handler answers one SMB1 command. It is responsible for writing the
// reply (usually via reply/replyDP) or deliberately sending none.
type smb1Handler func(ss *smbServer, req *smb1Request) error

// smb1Handlers maps an SMB1 command code to its handler. Commands not listed
// get a bare success header (smbServer.replyHeaderOnly). To support a new
// command, add parsing/response code to protocols/tcp/smb, annotate the read
// frame in describeSMB1 if it carries something worth logging, and register a
// handler here.
var smb1Handlers = map[byte]smb1Handler{
	smb.CmdNegotiate:             (*smbServer).negotiate,
	smb.CmdSessionSetupAndX:      (*smbServer).sessionSetup,
	smb.CmdTreeConnectAndX:       (*smbServer).treeConnect,
	smb.CmdNtCreateAndX:          (*smbServer).ntCreate,
	smb.CmdTransaction:           (*smbServer).transaction,
	smb.CmdTransaction2:          (*smbServer).transaction2,
	smb.CmdNtTransact:            (*smbServer).ntTransact,
	smb.CmdTransactionSecondary:  (*smbServer).transactionSecondary,
	smb.CmdTransaction2Secondary: (*smbServer).transactionSecondary,
	smb.CmdNtTransactSecondary:   (*smbServer).transactionSecondary,
	smb.CmdWriteAndX:             (*smbServer).writeAndX,
	smb.CmdWrite:                 (*smbServer).writeCmd,
	smb.CmdReadAndX:              (*smbServer).readAndX,
	smb.CmdClose:                 (*smbServer).closeCmd,
	smb.CmdEcho:                  (*smbServer).echo,
}

func (ss *smbServer) handleSMB1(frame smbFrame) error {
	pdu := frame.pdu()
	smbBuf := bytes.NewBuffer(pdu)
	header := smb.SMBHeader{}
	if err := smb.ParseHeader(smbBuf, &header); err != nil {
		ss.recordRead(frame, parsedSMB{})
		ss.logger.Debug("Failed to parse SMB header", slog.String("protocol", "smb"), producer.ErrAttr(err))
		return nil
	}
	req := &smb1Request{frame: frame, header: header, pdu: pdu, body: smbBuf.Bytes()}
	req.readIdx = ss.recordRead(frame, describeSMB1(header, req.body))
	ss.logger.Debug("SMB Header", slog.Any("header", header), slog.String("protocol", "smb"))

	handle, ok := smb1Handlers[header.Command]
	if !ok {
		handle = (*smbServer).replyHeaderOnly
	}
	return handle(ss, req)
}

// describeSMB1 extracts the request fields logged on the read frame. It only
// parses; session state is updated by the command handlers.
func describeSMB1(header smb.SMBHeader, body []byte) parsedSMB {
	ev := parsedSMB{
		Header:  header,
		Command: smb.CommandName(header.Command),
	}
	switch header.Command {
	case smb.CmdNtCreateAndX:
		ev.Path = smb.NtCreateAndXName(header, body)
	case smb.CmdTreeConnectAndX:
		ev.Path = smb.TreeConnectShare(header, body)
	case smb.CmdSessionSetupAndX:
		id := smb.SessionSetupIdentity(header, body)
		ev.Account = id.Account
		ev.Password = id.Password
		ev.LMResponse = id.LMResponse
		ev.NTLMResponse = id.NTLMResponse
		ev.NativeOS = id.NativeOS
		ev.NativeLanMan = id.NativeLanMan
	case smb.CmdTransaction2:
		if s, ok := smb.Trans2Setup(body); ok {
			ev.Setup = smb.Trans2SetupName(s)
			if s == smb.Trans2SessionSetup {
				ev.TotalDataCount = smb.Trans2TotalDataCount(body)
			}
		}
	case smb.CmdNtTransact:
		ev.TotalDataCount = smb.NtTransactTotalDataCount(body)
	}
	return ev
}

// reply writes a response built by one of the smb.Make* functions.
func (ss *smbServer) reply(header smb.SMBHeader, resp []byte, err error) error {
	if err != nil {
		return err
	}
	return ss.write(header, resp)
}

func (ss *smbServer) replyHeaderOnly(req *smb1Request) error {
	return ss.reply(smb.MakeHeaderResponse(req.header))
}

func (ss *smbServer) negotiate(req *smb1Request) error {
	var dialects []byte
	if parsed, err := smb.ParseNegotiateProtocolRequest(bytes.NewBuffer(req.body), req.header); err == nil {
		dialects = parsed.Data.DialectString
	}
	return ss.reply(smb.MakeNegotiateProtocolResponse(req.header, dialects))
}

// sessionSetup answers an SMB1 Session Setup AndX. Extended-security requests
// (WordCount 12) drive the NTLMSSP challenge/accept exchange and record the
// authenticating identity; basic requests get the plain response.
func (ss *smbServer) sessionSetup(req *smb1Request) error {
	header := req.header
	if len(req.body) == 0 || req.body[0] != 12 {
		return ss.reply(smb.MakeSessionSetupAndXResponse(header, ss.nextUID()))
	}
	accept := func() error {
		return ss.reply(smb.MakeSessionSetupESecResponse(header, ss.sessionUID(header), smb.SPNEGOAccept(), false))
	}
	ntlm, ok := smb.FindNTLMSSP(req.body)
	if !ok {
		// Extended security without NTLMSSP (e.g. Kerberos): accept.
		return accept()
	}
	switch smb.NTLMMessageType(ntlm) {
	case 1:
		ss.ensureChallenge()
		blob := smb.SPNEGOChallenge(smb.BuildChallenge(ss.challenge, smbTargetName))
		return ss.reply(smb.MakeSessionSetupESecResponse(header, ss.sessionUID(header), blob, true))
	case 3:
		ss.recordNTLMIdentity(smb.ParseAuthenticate(ntlm), req.readIdx)
	}
	return accept()
}

func (ss *smbServer) treeConnect(req *smb1Request) error {
	share := req.read(ss).Path
	if smb.IsProbeShare(share) {
		return ss.reply(smb.MakeBadNetworkNameResponse(req.header))
	}
	tid := ss.nextTID()
	ss.tidIsIPC[tid] = smb.IsIPCShare(share)
	return ss.reply(smb.MakeTreeConnectAndXResponse(req.header, tid, share))
}

// ntCreate opens a handle: a named pipe on an IPC$ tree, a disk file
// otherwise.
func (ss *smbServer) ntCreate(req *smb1Request) error {
	tid := binary.LittleEndian.Uint16(req.header.TID[:])
	isPipe := ss.tidIsIPC[tid]
	fid := ss.nextFID()
	ss.handles[fid] = &smbHandle{name: req.read(ss).Path, isPipe: isPipe, createEvt: req.readIdx}
	return ss.reply(smb.MakeNtCreateAndXResponse(req.header, fid, isPipe))
}

func (ss *smbServer) writeAndX(req *smb1Request) error {
	data := smb.WriteAndXData(req.pdu)
	if hn := ss.handles[smb.WriteAndXFID(req.body)]; hn != nil {
		if hn.isPipe {
			ss.feedPipe(hn, data, req.readIdx)
		} else {
			hn.captureFile(data)
		}
	}
	return ss.reply(smb.MakeWriteAndXResponse(req.header, smb.WriteAndXDataLength(req.body)))
}

func (ss *smbServer) writeCmd(req *smb1Request) error {
	data := smb.WriteData(req.pdu)
	if hn := ss.handles[smb.WriteFID(req.body)]; hn != nil && !hn.isPipe {
		hn.captureFile(data)
	}
	return ss.reply(smb.MakeWriteResponse(req.header, uint16(len(data))))
}

// readAndX serves a pending DCERPC reply from a named pipe, or no data.
func (ss *smbServer) readAndX(req *smb1Request) error {
	if hn := ss.handles[smb.ReadAndXFID(req.body)]; hn != nil && hn.isPipe && len(hn.rpcOut) > 0 {
		out := hn.rpcOut
		hn.rpcOut = nil
		return ss.reply(smb.MakeReadAndXDataResponse(req.header, out))
	}
	return ss.reply(smb.MakeReadAndXResponse(req.header))
}

func (ss *smbServer) closeCmd(req *smb1Request) error {
	ss.closeHandle(smb.CloseFID(req.body))
	return ss.replyHeaderOnly(req)
}

func (ss *smbServer) echo(req *smb1Request) error {
	return ss.reply(smb.MakeEchoResponse(req.header, req.body))
}
