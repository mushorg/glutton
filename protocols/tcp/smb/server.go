package smb

// Server is the per-connection SMB emulation, split by concern:
//
//	server.go              session state, framing, dispatch by dialect
//	server_commands.go     SMB1 request annotation and per-command replies
//	server_transaction.go  TRANS/TRANS2/NT_TRANSACT payload reassembly and capture
//	server_doublepulsar.go DoublePulsar backdoor emulation and XOR-key recovery
//	server_handles.go      open files and named pipes (uploads, DCERPC)
//
// The connection lifecycle (timeouts, the read loop bound, producing the event,
// closing) stays in protocols/tcp/smb.go.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"

	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/recall"
)

const (
	// MaxMessage is how many bytes of one NBSS message are kept; the rest is
	// read and discarded, and the frame is marked truncated.
	MaxMessage = 256 * 1024
	// DefaultMaxFileBuffer bounds the bytes captured per uploaded file.
	DefaultMaxFileBuffer = 8 * 1024 * 1024

	maxClaimedLen = 16 * 1024 * 1024
	maxTxBuffer   = 4 * 1024 * 1024
)

// Event is one decoded frame of an SMB session. Field names and json tags are
// the contract with downstream consumers; keep them stable.
type Event struct {
	Direction      string    `json:"direction,omitempty"`
	Header         SMBHeader `json:"header,omitempty"`
	Command        string    `json:"command,omitempty"`
	Path           string    `json:"path,omitempty"`
	Setup          string    `json:"setup,omitempty"`
	Status         string    `json:"status,omitempty"`
	NTStatus       uint32    `json:"nt_status,omitempty"`
	Account        string    `json:"account,omitempty"`
	Password       string    `json:"password,omitempty"`      // plaintext password from a basic Session Setup
	LMResponse     string    `json:"lm_response,omitempty"`   // hex LM/LMv2 response from a basic Session Setup
	NTLMResponse   string    `json:"ntlm_response,omitempty"` // hex NTLM/NTLMv2 response from a basic Session Setup
	NativeOS       string    `json:"native_os,omitempty"`
	NativeLanMan   string    `json:"native_lanman,omitempty"`
	Domain         string    `json:"domain,omitempty"`
	Workstation    string    `json:"workstation,omitempty"`
	CalledName     string    `json:"called_name,omitempty"`
	CallingName    string    `json:"calling_name,omitempty"`
	DCERPC         string    `json:"dcerpc,omitempty"`
	Interface      string    `json:"interface,omitempty"`
	InterfaceVer   string    `json:"interface_version,omitempty"`
	Opnum          *uint16   `json:"opnum,omitempty"`
	TotalDataCount uint32    `json:"total_data_count,omitempty"`
	PayloadHash    string    `json:"payload_hash,omitempty"`
	Shellcode      []string  `json:"shellcode,omitempty"`    // shellcode heuristics that matched the captured payload
	XORKey         string    `json:"xor_key,omitempty"`      // recovered DoublePulsar XOR key (hex)
	DecodedHash    string    `json:"decoded_hash,omitempty"` // content hash of the de-obfuscated payload
	Payload        []byte    `json:"payload,omitempty"`
	Truncated      bool      `json:"truncated,omitempty"`
	Variant        string    `json:"variant,omitempty"` // DoublePulsar reply variant, on emulated replies only
	Visit          int       `json:"visit,omitempty"`   // source's visit number, on emulated replies only
}

// Config wires a Server to its connection and its injectable dependencies.
// Zero-valued dependencies fall back to the production defaults.
type Config struct {
	Conn   net.Conn
	Logger interfaces.Logger
	SrcIP  net.IP

	// Store saves a captured artifact and returns its content hash.
	Store func(data []byte, folder string) (string, error)
	// ReadRand fills the NTLM challenge and the DoublePulsar signature.
	ReadRand func([]byte) (int, error)
	// Recall is the visit memory that picks the response variant.
	Recall *recall.Store
	// MaxFileBuffer bounds the bytes captured per uploaded file.
	MaxFileBuffer int
}

// Server holds the state of one SMB connection. It records every frame read
// and written; Events returns them once the connection ends.
type Server struct {
	events []Event
	conn   net.Conn
	logger interfaces.Logger

	store         func(data []byte, folder string) (string, error)
	readRand      func([]byte) (int, error)
	maxFileBuffer int

	// Session state handed out to the client.
	uid          uint16
	tid          uint16
	fid          uint16
	tidIsIPC     map[uint16]bool
	handles      map[uint16]*fileHandle
	challenge    [8]byte
	challengeSet bool

	// tx is the transaction payload currently being reassembled.
	tx txState

	// Recall: the variant is picked once per connection.
	srcIP   net.IP
	visit   int // 0 until begin
	variant Variant
	visits  *recall.Store

	// DoublePulsar emulation state.
	dpKey     uint32 // XOR key derived from the signature we sent in the ping reply
	dpKeySet  bool
	dpArchX64 bool
	dpOps     []string // opcodes seen, for the recall summary
}

// NewServer starts the emulation for one connection and picks its response
// variant from the visit memory.
func NewServer(cfg Config) *Server {
	ss := &Server{
		events:        []Event{},
		conn:          cfg.Conn,
		logger:        cfg.Logger,
		store:         cfg.Store,
		readRand:      cfg.ReadRand,
		maxFileBuffer: cfg.MaxFileBuffer,
		tidIsIPC:      map[uint16]bool{},
		handles:       map[uint16]*fileHandle{},
		srcIP:         cfg.SrcIP,
		visits:        cfg.Recall,
	}
	if ss.store == nil {
		ss.store = helpers.Store
	}
	if ss.readRand == nil {
		ss.readRand = rand.Read
	}
	if ss.maxFileBuffer == 0 {
		ss.maxFileBuffer = DefaultMaxFileBuffer
	}
	if ss.visits == nil {
		ss.visits = recall.Shared
	}
	ss.begin()
	return ss
}

// Events returns the frames recorded so far.
func (ss *Server) Events() []Event {
	return ss.events
}

// Finish stores any half-reassembled transaction and records the visit. Call
// it once, when the connection ends and before producing Events.
func (ss *Server) Finish() {
	ss.flushTx()
	ss.note()
}

// Frame is one NBSS packet as read off the wire: the 4-byte NBSS header
// followed by (at most MaxMessage bytes of) the message.
type Frame struct {
	payload   []byte
	truncated bool
}

// pdu is the message after the NBSS header.
func (f Frame) pdu() []byte {
	if len(f.payload) <= 4 {
		return nil
	}
	return f.payload[4:]
}

// ReadFrame reads one NBSS packet from the connection.
func (ss *Server) ReadFrame() (Frame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(ss.conn, hdr[:]); err != nil {
		return Frame{}, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	// Only NBSS control packets (keepalive) may be empty.
	if n > maxClaimedLen || (n == 0 && hdr[0] == NBSSSessionMessage) {
		return Frame{}, fmt.Errorf("invalid SMB message length: %d", n)
	}
	store := min(n, MaxMessage)
	truncated := store < n
	payload := make([]byte, 4+store)
	copy(payload[:4], hdr[:])
	if _, err := io.ReadFull(ss.conn, payload[4:]); err != nil {
		return Frame{}, err
	}
	if truncated {
		if _, err := io.CopyN(io.Discard, ss.conn, int64(n-store)); err != nil {
			return Frame{}, err
		}
	}
	return Frame{payload: payload, truncated: truncated}, nil
}

// HandleFrame records one NBSS packet and answers it by dialect. An error
// means a reply could not be written.
func (ss *Server) HandleFrame(frame Frame) error {
	pdu := frame.pdu()
	switch {
	case frame.payload[0] != NBSSSessionMessage:
		return ss.handleNBSS(frame)
	case bytes.HasPrefix(pdu, []byte("\xffSMB")):
		return ss.handleSMB1(frame)
	case bytes.HasPrefix(pdu, []byte("\xfeSMB")):
		return ss.handleSMB2(frame)
	case bytes.HasPrefix(pdu, []byte("\xfdSMB")):
		// Encrypted SMB3: nothing to parse without the session key.
		ss.recordRead(frame, Event{Command: "SMB3_TRANSFORM"})
	default:
		ss.recordRead(frame, Event{})
	}
	return nil
}

// handleNBSS records a NetBIOS session control packet (port 139 framing) and
// accepts session requests so the client continues with SMB Negotiate.
func (ss *Server) handleNBSS(frame Frame) error {
	ev := Event{Command: NBSSTypeName(frame.payload[0])}
	if frame.payload[0] != NBSSSessionRequest {
		ss.recordRead(frame, ev)
		return nil
	}
	ev.CalledName, ev.CallingName, _ = ParseSessionRequest(frame.pdu())
	ss.recordRead(frame, ev)
	return ss.writeNBSS(MakePositiveSessionResponse())
}

func (ss *Server) handleSMB2(frame Frame) error {
	pdu := frame.pdu()
	ss.ensureChallenge()
	name, resp, ok := MakeSMB2Reply(pdu, ss.challenge)
	if name == "" {
		name = "SMB2"
	}
	readIdx := ss.recordRead(frame, Event{Command: name})
	// Record the identity from an SMB2 NTLMSSP AUTHENTICATE (no secrets).
	if ntlm, found := FindNTLMSSP(pdu); found && NTLMMessageType(ntlm) == 3 {
		ss.recordNTLMIdentity(ParseAuthenticate(ntlm), readIdx)
	}
	if !ok {
		return nil
	}
	return ss.writePDU(name, SMBHeader{}, resp)
}

// recordRead appends ev as a read frame carrying the raw frame bytes and
// returns its index, so later processing can annotate it.
func (ss *Server) recordRead(frame Frame, ev Event) int {
	ev.Direction = "read"
	ev.Payload = frame.payload
	ev.Truncated = frame.truncated
	ss.events = append(ss.events, ev)
	return len(ss.events) - 1
}

// event returns the frame at idx, or nil when idx is out of range. Indexes
// stay valid as events are appended; pointers do not, so callers must not
// hold on to the result across an append.
func (ss *Server) event(idx int) *Event {
	if idx < 0 || idx >= len(ss.events) {
		return nil
	}
	return &ss.events[idx]
}

func (ss *Server) write(header SMBHeader, data []byte) error {
	return ss.writePDU(CommandName(header.Command), header, data)
}

func (ss *Server) writePDU(command string, header SMBHeader, data []byte) error {
	framed := WrapSessionMessage(data)
	if _, err := ss.conn.Write(framed); err != nil {
		return err
	}
	ss.events = append(ss.events, Event{
		Direction: "write",
		Header:    header,
		Command:   command,
		Status:    StatusName(header),
		NTStatus:  NTStatus(header),
		Payload:   framed,
	})
	return nil
}

// writeNBSS sends a NetBIOS session control packet (already framed).
func (ss *Server) writeNBSS(data []byte) error {
	if _, err := ss.conn.Write(data); err != nil {
		return err
	}
	ss.events = append(ss.events, Event{
		Direction: "write",
		Command:   NBSSTypeName(data[0]),
		Payload:   data,
	})
	return nil
}

// storePayload saves a captured artifact and returns its content hash.
func (ss *Server) storePayload(data []byte, what string) (string, bool) {
	hash, err := ss.store(data, filepath.Join("payloads", "smb"))
	if err != nil {
		ss.logger.Error("Failed to store "+what, slog.String("protocol", "smb"), producer.ErrAttr(err))
		return "", false
	}
	return hash, true
}

// begin picks the response variant once per connection: a source returning
// after recall.visit_gap gets the next Variants entry.
func (ss *Server) begin() {
	if ss.visit > 0 {
		return
	}
	v := ss.visits.Begin("smb", ss.srcIP, len(Variants))
	ss.visit, ss.variant = v.Number, Variants[v.Variant]
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
func (ss *Server) note() {
	if ss.visit == 0 {
		return
	}
	ss.visits.Note("smb", ss.srcIP, func(sum *recall.Summary) {
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

func (ss *Server) ensureChallenge() {
	if !ss.challengeSet {
		_, _ = ss.readRand(ss.challenge[:])
		ss.challengeSet = true
	}
}

// sessionUID reuses the UID the client echoes back (NTLM step 2) or assigns a
// fresh one on the first Session Setup.
func (ss *Server) sessionUID(header SMBHeader) uint16 {
	if uid := binary.LittleEndian.Uint16(header.UID[:]); uid != 0 {
		return uid
	}
	return ss.nextUID()
}

func (ss *Server) nextUID() uint16 {
	ss.uid++
	return ss.uid
}

func (ss *Server) nextTID() uint16 {
	ss.tid++
	return ss.tid
}

func (ss *Server) nextFID() uint16 {
	ss.fid++
	return ss.fid
}

// recordNTLMIdentity sets the NTLMSSP Type 3 identity fields on a read frame.
// The NTLM responses stay in the raw payload.
func (ss *Server) recordNTLMIdentity(id NTLMIdentity, readIdx int) {
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
