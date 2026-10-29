package tcp

// The SMB handler is split by concern:
//
//	smb.go             session state, framing, the read loop, dispatch by dialect
//	smb_commands.go    SMB1 request annotation and per-command replies
//	smb_transaction.go TRANS/TRANS2/NT_TRANSACT payload reassembly and capture
//	smb_doublepulsar.go DoublePulsar backdoor emulation and XOR-key recovery
//	smb_handles.go     open files and named pipes (uploads, DCERPC)
//
// Byte-level parsing and response construction live in protocols/tcp/smb.

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
	"github.com/mushorg/glutton/protocols/recall"
	"github.com/mushorg/glutton/protocols/tcp/smb"
)

const (
	maxSMBMessage    = 256 * 1024
	maxSMBMessages   = 128
	maxSMBClaimedLen = 16 * 1024 * 1024
	maxSMBTxBuffer   = 4 * 1024 * 1024
)

var maxSMBFileBuffer = 8 * 1024 * 1024

// Seams for tests: artifact storage, randomness (NTLM challenge, DoublePulsar
// signature), and the visit memory (swapped for a store with a fake clock).
var (
	smbStore    = helpers.Store
	smbReadRand = rand.Read
	smbRecall   = recall.Shared
)

type parsedSMB struct {
	Direction      string        `json:"direction,omitempty"`
	Header         smb.SMBHeader `json:"header,omitempty"`
	Command        string        `json:"command,omitempty"`
	Path           string        `json:"path,omitempty"`
	Setup          string        `json:"setup,omitempty"`
	Status         string        `json:"status,omitempty"`
	NTStatus       uint32        `json:"nt_status,omitempty"`
	Account        string        `json:"account,omitempty"`
	Password       string        `json:"password,omitempty"`      // plaintext password from a basic Session Setup
	LMResponse     string        `json:"lm_response,omitempty"`   // hex LM/LMv2 response from a basic Session Setup
	NTLMResponse   string        `json:"ntlm_response,omitempty"` // hex NTLM/NTLMv2 response from a basic Session Setup
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
	Shellcode      []string      `json:"shellcode,omitempty"`    // shellcode heuristics that matched the captured payload
	XORKey         string        `json:"xor_key,omitempty"`      // recovered DoublePulsar XOR key (hex)
	DecodedHash    string        `json:"decoded_hash,omitempty"` // content hash of the de-obfuscated payload
	Payload        []byte        `json:"payload,omitempty"`
	Truncated      bool          `json:"truncated,omitempty"`
	Variant        string        `json:"variant,omitempty"` // DoublePulsar reply variant, on emulated replies only
	Visit          int           `json:"visit,omitempty"`   // source's visit number, on emulated replies only
}

type smbServer struct {
	events []parsedSMB
	conn   net.Conn
	logger interfaces.Logger

	// Session state handed out to the client.
	uid          uint16
	tid          uint16
	fid          uint16
	tidIsIPC     map[uint16]bool
	handles      map[uint16]*smbHandle
	challenge    [8]byte
	challengeSet bool

	// tx is the transaction payload currently being reassembled.
	tx smbTx

	// Recall: the variant is picked once per connection.
	srcIP   net.IP
	visit   int // 0 until begin
	variant smb.Variant
	store   *recall.Store

	// DoublePulsar emulation state.
	dpKey     uint32 // XOR key derived from the signature we sent in the ping reply
	dpKeySet  bool
	dpArchX64 bool
	dpOps     []string // opcodes seen, for the recall summary
}

// smbFrame is one NBSS packet as read off the wire: the 4-byte NBSS header
// followed by (at most maxSMBMessage bytes of) the message.
type smbFrame struct {
	payload   []byte
	truncated bool
}

// pdu is the message after the NBSS header.
func (f smbFrame) pdu() []byte {
	if len(f.payload) <= 4 {
		return nil
	}
	return f.payload[4:]
}

// HandleSMB takes a net.Conn and does basic SMB communication
func HandleSMB(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &smbServer{
		events:   []parsedSMB{},
		conn:     conn,
		logger:   logger,
		tidIsIPC: map[uint16]bool{},
		handles:  map[uint16]*smbHandle{},
		srcIP:    remoteIP(conn),
	}
	server.begin()
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		server.flushTx()
		server.note()
		if err := h.ProduceTCP("smb", conn, md, helpers.FirstOrEmpty[parsedSMB](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "smb"), producer.ErrAttr(err))
		}

		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close SMB connection", producer.ErrAttr(err), slog.String("protocol", "smb"))
		}
	}()

	for i := 0; i < maxSMBMessages; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "smb"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		frame, err := server.read()
		if err != nil {
			logger.Debug("Failed to read data", slog.String("protocol", "smb"), producer.ErrAttr(err))
			endReason = connection.EndReasonFromRead(err)
			return nil
		}
		if err := server.handleFrame(frame); err != nil {
			endReason = connection.EndWriteError
			return err
		}
	}
	endReason = connection.EndMaxFrames
	return nil
}

// handleFrame records one NBSS packet and answers it by dialect.
func (ss *smbServer) handleFrame(frame smbFrame) error {
	pdu := frame.pdu()
	switch {
	case frame.payload[0] != smb.NBSSSessionMessage:
		return ss.handleNBSS(frame)
	case bytes.HasPrefix(pdu, []byte("\xffSMB")):
		return ss.handleSMB1(frame)
	case bytes.HasPrefix(pdu, []byte("\xfeSMB")):
		return ss.handleSMB2(frame)
	case bytes.HasPrefix(pdu, []byte("\xfdSMB")):
		// Encrypted SMB3: nothing to parse without the session key.
		ss.recordRead(frame, parsedSMB{Command: "SMB3_TRANSFORM"})
	default:
		ss.recordRead(frame, parsedSMB{})
	}
	return nil
}

// handleNBSS records a NetBIOS session control packet (port 139 framing) and
// accepts session requests so the client continues with SMB Negotiate.
func (ss *smbServer) handleNBSS(frame smbFrame) error {
	ev := parsedSMB{Command: smb.NBSSTypeName(frame.payload[0])}
	if frame.payload[0] != smb.NBSSSessionRequest {
		ss.recordRead(frame, ev)
		return nil
	}
	ev.CalledName, ev.CallingName, _ = smb.ParseSessionRequest(frame.pdu())
	ss.recordRead(frame, ev)
	return ss.writeNBSS(smb.MakePositiveSessionResponse())
}

func (ss *smbServer) handleSMB2(frame smbFrame) error {
	pdu := frame.pdu()
	ss.ensureChallenge()
	name, resp, ok := smb.MakeSMB2Reply(pdu, ss.challenge)
	if name == "" {
		name = "SMB2"
	}
	readIdx := ss.recordRead(frame, parsedSMB{Command: name})
	// Record the identity from an SMB2 NTLMSSP AUTHENTICATE (no secrets).
	if ntlm, found := smb.FindNTLMSSP(pdu); found && smb.NTLMMessageType(ntlm) == 3 {
		ss.recordNTLMIdentity(smb.ParseAuthenticate(ntlm), readIdx)
	}
	if !ok {
		return nil
	}
	return ss.writePDU(name, smb.SMBHeader{}, resp)
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
	store := min(n, maxSMBMessage)
	truncated := store < n
	payload := make([]byte, 4+store)
	copy(payload[:4], hdr[:])
	if _, err := io.ReadFull(ss.conn, payload[4:]); err != nil {
		return smbFrame{}, err
	}
	if truncated {
		if _, err := io.CopyN(io.Discard, ss.conn, int64(n-store)); err != nil {
			return smbFrame{}, err
		}
	}
	return smbFrame{payload: payload, truncated: truncated}, nil
}

// recordRead appends ev as a read frame carrying the raw frame bytes and
// returns its index, so later processing can annotate it.
func (ss *smbServer) recordRead(frame smbFrame, ev parsedSMB) int {
	ev.Direction = "read"
	ev.Payload = frame.payload
	ev.Truncated = frame.truncated
	ss.events = append(ss.events, ev)
	return len(ss.events) - 1
}

// event returns the frame at idx, or nil when idx is out of range. Indexes
// stay valid as events are appended; pointers do not, so callers must not
// hold on to the result across an append.
func (ss *smbServer) event(idx int) *parsedSMB {
	if idx < 0 || idx >= len(ss.events) {
		return nil
	}
	return &ss.events[idx]
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

// storePayload saves a captured artifact and returns its content hash.
func (ss *smbServer) storePayload(data []byte, what string) (string, bool) {
	hash, err := smbStore(data, filepath.Join("payloads", "smb"))
	if err != nil {
		ss.logger.Error("Failed to store "+what, slog.String("protocol", "smb"), producer.ErrAttr(err))
		return "", false
	}
	return hash, true
}

// begin picks the response variant once per connection: a source returning
// after recall.visit_gap gets the next smb.Variants entry.
func (ss *smbServer) begin() {
	if ss.visit > 0 {
		return
	}
	ss.store = smbRecall
	v := ss.store.Begin("smb", ss.srcIP, len(smb.Variants))
	ss.visit, ss.variant = v.Number, smb.Variants[v.Variant]
	if v.Started && v.Number > 1 {
		ss.logger.Info("returning SMB source",
			slog.String("protocol", "smb"),
			slog.String("src_ip", ss.srcIP.String()),
			slog.Int("visit", v.Number),
			slog.String("variant", ss.variant.String()),
			slog.String("previous_variant", v.Previous.Variant),
			slog.Any("previous_commands", v.Previous.Commands),
		)
	}
}

// note stores what the source did on this connection.
func (ss *smbServer) note() {
	if ss.visit == 0 {
		return
	}
	ss.store.Note("smb", ss.srcIP, func(sum *recall.Summary) {
		sum.Variant = ss.variant.String()
		sum.Events++
		for _, e := range ss.events {
			if e.Direction != "read" {
				continue
			}
			sum.AddCommand(e.Command)
			sum.AddPath(e.Path)
		}
		for _, op := range ss.dpOps {
			sum.AddCommand(op)
		}
	})
}

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

// recordNTLMIdentity sets the NTLMSSP Type 3 identity fields on a read frame.
// The NTLM responses stay in the raw payload.
func (ss *smbServer) recordNTLMIdentity(id smb.NTLMIdentity, readIdx int) {
	ev := ss.event(readIdx)
	if ev == nil {
		return
	}
	if id.User != "" {
		ev.Account = id.User
	}
	ev.Domain = id.Domain
	ev.Workstation = id.Workstation
}
