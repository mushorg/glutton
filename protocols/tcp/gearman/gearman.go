// Package gearman parses Gearman job-server packets (binary and text admin
// protocol) and builds the canned replies the honeypot sends.
//
// Binary packets: 4-byte magic ("\0REQ" from clients, "\0RES" from the
// server), 4-byte big-endian packet type, 4-byte big-endian data size, then
// the data with arguments separated by NUL bytes. Lines that do not start
// with NUL are admin text commands (version, status, workers, ...).
package gearman

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// HeaderSize is the size of the binary packet header.
	HeaderSize = 12
	// MaxBodySize caps the data section the honeypot reads per packet.
	MaxBodySize = 64 * 1024
)

var (
	MagicReq = []byte("\x00REQ")
	MagicRes = []byte("\x00RES")

	ErrBadMagic = errors.New("gearman: bad packet magic")
	ErrTooLarge = errors.New("gearman: packet data too large")
)

// Packet types (gearman.org PROTOCOL document).
const (
	CanDo           uint32 = 1
	CantDo          uint32 = 2
	ResetAbilities  uint32 = 3
	PreSleep        uint32 = 4
	Noop            uint32 = 6
	SubmitJob       uint32 = 7
	JobCreated      uint32 = 8
	GrabJob         uint32 = 9
	NoJob           uint32 = 10
	JobAssign       uint32 = 11
	WorkStatus      uint32 = 12
	WorkComplete    uint32 = 13
	WorkFail        uint32 = 14
	GetStatus       uint32 = 15
	EchoReq         uint32 = 16
	EchoRes         uint32 = 17
	SubmitJobBg     uint32 = 18
	Error           uint32 = 19
	StatusRes       uint32 = 20
	SubmitJobHigh   uint32 = 21
	SetClientID     uint32 = 22
	CanDoTimeout    uint32 = 23
	AllYours        uint32 = 24
	WorkException   uint32 = 25
	OptionReq       uint32 = 26
	OptionRes       uint32 = 27
	WorkData        uint32 = 28
	WorkWarning     uint32 = 29
	GrabJobUniq     uint32 = 30
	JobAssignUniq   uint32 = 31
	SubmitJobHighBg uint32 = 32
	SubmitJobLow    uint32 = 33
	SubmitJobLowBg  uint32 = 34
	SubmitJobSched  uint32 = 35
	SubmitJobEpoch  uint32 = 36
	GrabJobAll      uint32 = 39
	JobAssignAll    uint32 = 40
)

var typeNames = map[uint32]string{
	CanDo: "CAN_DO", CantDo: "CANT_DO", ResetAbilities: "RESET_ABILITIES",
	PreSleep: "PRE_SLEEP", Noop: "NOOP", SubmitJob: "SUBMIT_JOB",
	JobCreated: "JOB_CREATED", GrabJob: "GRAB_JOB", NoJob: "NO_JOB",
	JobAssign: "JOB_ASSIGN", WorkStatus: "WORK_STATUS", WorkComplete: "WORK_COMPLETE",
	WorkFail: "WORK_FAIL", GetStatus: "GET_STATUS", EchoReq: "ECHO_REQ",
	EchoRes: "ECHO_RES", SubmitJobBg: "SUBMIT_JOB_BG", Error: "ERROR",
	StatusRes: "STATUS_RES", SubmitJobHigh: "SUBMIT_JOB_HIGH", SetClientID: "SET_CLIENT_ID",
	CanDoTimeout: "CAN_DO_TIMEOUT", AllYours: "ALL_YOURS", WorkException: "WORK_EXCEPTION",
	OptionReq: "OPTION_REQ", OptionRes: "OPTION_RES", WorkData: "WORK_DATA",
	WorkWarning: "WORK_WARNING", GrabJobUniq: "GRAB_JOB_UNIQ", JobAssignUniq: "JOB_ASSIGN_UNIQ",
	SubmitJobHighBg: "SUBMIT_JOB_HIGH_BG", SubmitJobLow: "SUBMIT_JOB_LOW",
	SubmitJobLowBg: "SUBMIT_JOB_LOW_BG", SubmitJobSched: "SUBMIT_JOB_SCHED",
	SubmitJobEpoch: "SUBMIT_JOB_EPOCH", GrabJobAll: "GRAB_JOB_ALL", JobAssignAll: "JOB_ASSIGN_ALL",
}

// argCounts is the number of NUL-separated arguments per request type; the
// last argument keeps any further NUL bytes. Types not listed carry one
// opaque argument (or none when the size is zero).
var argCounts = map[uint32]int{
	SubmitJob: 3, SubmitJobBg: 3, SubmitJobHigh: 3, SubmitJobHighBg: 3,
	SubmitJobLow: 3, SubmitJobLowBg: 3,
	SubmitJobSched: 8, SubmitJobEpoch: 4,
	WorkStatus: 3, WorkComplete: 2, WorkData: 2, WorkWarning: 2, WorkException: 2,
	CanDoTimeout: 2,
	StatusRes:    5, Error: 2,
}

// TypeName returns the protocol name of a packet type, or UNKNOWN_<n>.
func TypeName(t uint32) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return "UNKNOWN_" + strconv.FormatUint(uint64(t), 10)
}

// Packet is one decoded binary packet.
type Packet struct {
	Magic string // "REQ" or "RES"
	Type  uint32
	Args  [][]byte
	Raw   []byte // header plus data as read from the wire
}

// Name is the packet type name.
func (p Packet) Name() string { return TypeName(p.Type) }

// Function returns the function name for SUBMIT_JOB* and CAN_DO* packets.
func (p Packet) Function() string {
	switch p.Type {
	case SubmitJob, SubmitJobBg, SubmitJobHigh, SubmitJobHighBg, SubmitJobLow,
		SubmitJobLowBg, SubmitJobSched, SubmitJobEpoch, CanDo, CantDo, CanDoTimeout:
		if len(p.Args) > 0 {
			return string(p.Args[0])
		}
	}
	return ""
}

// Unique returns the client-supplied unique ID of SUBMIT_JOB* packets.
func (p Packet) Unique() string {
	switch p.Type {
	case SubmitJob, SubmitJobBg, SubmitJobHigh, SubmitJobHighBg, SubmitJobLow,
		SubmitJobLowBg, SubmitJobSched, SubmitJobEpoch:
		if len(p.Args) > 1 {
			return string(p.Args[1])
		}
	}
	return ""
}

// Handle returns the job handle of packets that carry one first.
func (p Packet) Handle() string {
	switch p.Type {
	case JobCreated, GetStatus, StatusRes, WorkStatus, WorkComplete, WorkFail,
		WorkData, WorkWarning, WorkException:
		if len(p.Args) > 0 {
			return string(p.Args[0])
		}
	}
	return ""
}

// ReadPacket reads one binary packet. On ErrBadMagic or ErrTooLarge the
// returned packet still holds the 12 header bytes in Raw.
func ReadPacket(r io.Reader) (Packet, error) {
	hdr := make([]byte, HeaderSize)
	if n, err := io.ReadFull(r, hdr); err != nil {
		return Packet{Raw: hdr[:n]}, err
	}
	p := Packet{Type: binary.BigEndian.Uint32(hdr[4:8]), Raw: hdr}
	switch {
	case bytes.Equal(hdr[:4], MagicReq):
		p.Magic = "REQ"
	case bytes.Equal(hdr[:4], MagicRes):
		p.Magic = "RES"
	default:
		return p, ErrBadMagic
	}
	size := binary.BigEndian.Uint32(hdr[8:12])
	if size > MaxBodySize {
		return p, ErrTooLarge
	}
	raw := make([]byte, HeaderSize+int(size))
	copy(raw, hdr)
	if n, err := io.ReadFull(r, raw[HeaderSize:]); err != nil {
		p.Raw = raw[:HeaderSize+n]
		return p, err
	}
	p.Raw = raw
	p.Args = splitArgs(p.Type, raw[HeaderSize:])
	return p, nil
}

func splitArgs(t uint32, data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	n := argCounts[t]
	if n <= 1 {
		return [][]byte{data}
	}
	return bytes.SplitN(data, []byte{0}, n)
}

// Encode builds a binary packet with NUL-separated arguments.
func Encode(magic []byte, t uint32, args ...[]byte) []byte {
	data := bytes.Join(args, []byte{0})
	out := make([]byte, HeaderSize+len(data))
	copy(out, magic)
	binary.BigEndian.PutUint32(out[4:8], t)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(data)))
	copy(out[HeaderSize:], data)
	return out
}

// Server holds the per-connection state used to build replies.
type Server struct {
	Host    string // host part of job handles (H:<host>:<n>)
	Version string // admin "version" reply
	PID     int    // admin "getpid" reply
	jobs    int
}

// NewServer returns a Server with gearmand-like defaults.
func NewServer(host string) *Server {
	return &Server{Host: host, Version: "1.1.19.1", PID: 1187}
}

// Reply builds the server answer to a binary request, or nil when a real
// job server stays silent (worker registration, sleep, status updates).
func (s *Server) Reply(p Packet) []byte {
	if p.Magic != "REQ" {
		return nil
	}
	switch p.Type {
	case EchoReq:
		return Encode(MagicRes, EchoRes, p.Args...)
	case SubmitJob, SubmitJobBg, SubmitJobHigh, SubmitJobHighBg, SubmitJobLow,
		SubmitJobLowBg, SubmitJobSched, SubmitJobEpoch:
		s.jobs++
		return Encode(MagicRes, JobCreated, []byte(fmt.Sprintf("H:%s:%d", s.Host, s.jobs)))
	case GetStatus:
		handle := []byte{}
		if len(p.Args) > 0 {
			handle = p.Args[0]
		}
		// Unknown handle: known=0, running=0, numerator=0, denominator=0.
		return Encode(MagicRes, StatusRes, handle, []byte("0"), []byte("0"), []byte("0"), []byte("0"))
	case OptionReq:
		if len(p.Args) > 0 && string(p.Args[0]) == "exceptions" {
			return Encode(MagicRes, OptionRes, p.Args[0])
		}
		return Encode(MagicRes, Error, []byte("UNKNOWN_OPTION"), []byte("Server does not recognize given option"))
	case GrabJob, GrabJobUniq, GrabJobAll:
		return Encode(MagicRes, NoJob)
	case PreSleep, CanDo, CantDo, CanDoTimeout, ResetAbilities, SetClientID,
		WorkStatus, WorkComplete, WorkFail, WorkData, WorkWarning, WorkException, AllYours:
		return nil
	default:
		return Encode(MagicRes, Error, []byte("ERR_UNKNOWN_COMMAND"), []byte("Unknown+server+command"))
	}
}

// AdminCommand returns the lowercased first word of an admin text line.
func AdminCommand(line string) string {
	f := strings.Fields(line)
	if len(f) == 0 {
		return ""
	}
	return strings.ToLower(f[0])
}

// AdminReply answers an admin text command. clientIP is listed in the
// "workers" output as the admin connection itself. closeAfter is set for
// "shutdown"; the honeypot only closes the connection.
func (s *Server) AdminReply(line, clientIP string) (reply []byte, closeAfter bool) {
	switch AdminCommand(line) {
	case "":
		return nil, false
	case "version":
		return []byte("OK " + s.Version + "\n"), false
	case "getpid":
		return []byte("OK " + strconv.Itoa(s.PID) + "\n"), false
	case "status":
		return []byte(".\n"), false
	case "workers":
		return []byte("33 " + clientIP + " - :\n.\n"), false
	case "maxqueue", "verbose":
		return []byte("OK\n"), false
	case "shutdown":
		return []byte("OK\n"), true
	default:
		return []byte("ERR UNKNOWN_COMMAND Unknown+server+command\n"), false
	}
}
