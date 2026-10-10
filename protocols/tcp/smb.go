package tcp

import (
	"bytes"
	"context"
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
	TotalDataCount uint32        `json:"total_data_count,omitempty"`
	PayloadHash    string        `json:"payload_hash,omitempty"`
	Payload        []byte        `json:"payload,omitempty"`
	Truncated      bool          `json:"truncated,omitempty"`
}

type smbServer struct {
	events  []parsedSMB
	conn    net.Conn
	uid     uint16
	tid     uint16
	fid     uint16
	txTotal uint32
	txOpen  bool
	txBuf   []byte
	txEvent int
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
	if n <= 0 || n > maxSMBClaimedLen {
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

func smbPDU(frame smbFrame) []byte {
	if len(frame.payload) <= 4 {
		return nil
	}
	return frame.payload[4:]
}

// HandleSMB takes a net.Conn and does basic SMB communication
func HandleSMB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &smbServer{
		events: []parsedSMB{},
		conn:   conn,
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
		responseHeader, resp, err = smb.MakeSessionSetupAndXResponse(header, ss.nextUID())
	case smb.CmdTreeConnectAndX:
		share := smb.TreeConnectShare(header, smbBuf.Bytes())
		responseHeader, resp, err = smb.MakeTreeConnectAndXResponse(header, ss.nextTID(), share)
	case smb.CmdNtCreateAndX:
		responseHeader, resp, err = smb.MakeNtCreateAndXResponse(header, ss.nextFID())
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
		count := smb.WriteAndXDataLength(smbBuf.Bytes())
		responseHeader, resp, err = smb.MakeWriteAndXResponse(header, count)
	case smb.CmdReadAndX:
		responseHeader, resp, err = smb.MakeReadAndXResponse(header)
	case smb.CmdClose:
		responseHeader, resp, err = smb.MakeHeaderResponse(header)
	case smb.CmdEcho:
		responseHeader, resp, err = smb.MakeEchoResponse(header, smbBuf.Bytes())
	default:
		responseHeader, resp, err = smb.MakeHeaderResponse(header)
	}
	if err != nil {
		return err
	}
	return ss.write(responseHeader, resp)
}

func (ss *smbServer) handleSMB2(frame smbFrame, pdu []byte) error {
	name, resp, ok := smb.MakeSMB2Reply(pdu)
	if name == "" {
		name = "SMB2"
	}
	ss.events = append(ss.events, parsedSMB{
		Direction: "read",
		Command:   name,
		Payload:   frame.payload,
		Truncated: frame.truncated,
	})
	if !ok {
		return nil
	}
	return ss.writePDU(name, smb.SMBHeader{}, resp)
}
