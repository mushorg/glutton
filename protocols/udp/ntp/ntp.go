// Package ntp parses NTP datagrams (client/server packets, mode 6 control and
// mode 7 private requests) and builds minimal, never-amplifying replies.
package ntp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// NTP modes (low three bits of the first byte).
const (
	ModeSymActive  = 1
	ModeSymPassive = 2
	ModeClient     = 3
	ModeServer     = 4
	ModeBroadcast  = 5
	ModeControl    = 6
	ModePrivate    = 7
)

const (
	// PacketLen is the length of a plain client/server packet.
	PacketLen = 48
	// ControlHeaderLen is the mode 6 header length.
	ControlHeaderLen = 12
	// PrivateHeaderLen is the mode 7 header length.
	PrivateHeaderLen = 8

	// ntpEpochOffset is the seconds between 1900-01-01 and 1970-01-01.
	ntpEpochOffset = 2208988800

	// INFO_ERR_REQ: "unsupported request code", used for mode 7 replies.
	infoErrReq = 2
	// CERR_PERMISSION: used for mode 6 error replies.
	cerrPermission = 1
)

// ErrShort is returned for datagrams too short for their mode.
var ErrShort = errors.New("ntp: datagram too short")

// ErrMode is returned for modes that are not valid NTP (0, or reserved).
var ErrMode = errors.New("ntp: unsupported mode")

// Packet is the parsed header of an NTP datagram. Only fields that belong to
// the packet's mode are set.
type Packet struct {
	LeapIndicator int
	Version       int
	Mode          int

	// Modes 1-5.
	Stratum  int
	Poll     int
	Transmit uint64 // transmit timestamp, raw 64-bit NTP format

	// Mode 6.
	Response bool // also set for mode 7
	Error    bool
	More     bool
	Opcode   int
	Sequence int
	Status   int
	AssocID  int
	Offset   int
	Count    int

	// Mode 7.
	Auth      bool
	Impl      int
	ReqCode   int
	ErrCode   int
	NumItems  int
	ItemSize  int
	Remaining int // bytes after the mode 7 header
}

var controlOpcodes = map[int]string{
	1: "readstat", 2: "readvar", 3: "writevar", 4: "readclock", 5: "writeclock",
	6: "settrap", 7: "asyncmsg", 8: "configure", 9: "saveconfig", 10: "read_mru",
	11: "read_ordlist_a", 12: "req_nonce", 31: "unsettrap",
}

var privateRequests = map[int]string{
	0: "peer_list", 1: "peer_list_sum", 2: "peer_info", 3: "peer_stats", 4: "sys_info",
	5: "sys_stats", 6: "io_stats", 7: "mem_stats", 8: "loop_info", 9: "timer_stats",
	10: "config", 11: "unconfig", 12: "set_sys_flag", 13: "clr_sys_flag", 14: "monitor",
	15: "nomonitor", 16: "get_restrict", 17: "resaddflags", 18: "ressubflags", 19: "unrestrict",
	20: "mon_getlist", 21: "reset_stats", 22: "reset_peer", 23: "reread_keys",
	27: "authinfo", 28: "traps", 29: "add_trap", 30: "clr_trap", 31: "request_key",
	32: "control_key", 33: "get_ctlstats", 34: "get_leapinfo", 35: "get_clockinfo",
	36: "get_clkbuginfo", 37: "set_precision", 42: "mon_getlist_1", 43: "hostname_associd",
	44: "if_stats", 45: "if_reload",
}

var modeNames = map[int]string{
	ModeSymActive: "symmetric_active", ModeSymPassive: "symmetric_passive",
	ModeClient: "client", ModeServer: "server", ModeBroadcast: "broadcast",
}

// Parse decodes the NTP header of data. It is tolerant: it accepts any version.
func Parse(data []byte) (*Packet, error) {
	if len(data) < 1 {
		return nil, ErrShort
	}
	p := &Packet{
		LeapIndicator: int(data[0] >> 6),
		Version:       int(data[0] >> 3 & 7),
		Mode:          int(data[0] & 7),
	}
	switch p.Mode {
	case ModeSymActive, ModeSymPassive, ModeClient, ModeServer, ModeBroadcast:
		if len(data) < PacketLen {
			return nil, ErrShort
		}
		p.Stratum = int(data[1])
		p.Poll = int(int8(data[2]))
		p.Transmit = binary.BigEndian.Uint64(data[40:48])
	case ModeControl:
		if len(data) < ControlHeaderLen {
			return nil, ErrShort
		}
		p.Response = data[1]&0x80 != 0
		p.Error = data[1]&0x40 != 0
		p.More = data[1]&0x20 != 0
		p.Opcode = int(data[1] & 0x1f)
		p.Sequence = int(binary.BigEndian.Uint16(data[2:4]))
		p.Status = int(binary.BigEndian.Uint16(data[4:6]))
		p.AssocID = int(binary.BigEndian.Uint16(data[6:8]))
		p.Offset = int(binary.BigEndian.Uint16(data[8:10]))
		p.Count = int(binary.BigEndian.Uint16(data[10:12]))
	case ModePrivate:
		if len(data) < PrivateHeaderLen {
			return nil, ErrShort
		}
		p.Response = data[0]&0x80 != 0
		p.More = data[0]&0x40 != 0
		p.Auth = data[1]&0x80 != 0
		p.Sequence = int(data[1] & 0x7f)
		p.Impl = int(data[2])
		p.ReqCode = int(data[3])
		w := binary.BigEndian.Uint16(data[4:6])
		p.ErrCode = int(w >> 12)
		p.NumItems = int(w & 0x0fff)
		p.ItemSize = int(binary.BigEndian.Uint16(data[6:8]) & 0x0fff)
		p.Remaining = len(data) - PrivateHeaderLen
	default:
		return nil, ErrMode
	}
	return p, nil
}

// Command names the leaf operation: the mode for packets, the opcode for
// control messages, the request code for private requests.
func (p *Packet) Command() string {
	switch p.Mode {
	case ModeControl:
		if n, ok := controlOpcodes[p.Opcode]; ok {
			return n
		}
		return fmt.Sprintf("opcode_%d", p.Opcode)
	case ModePrivate:
		if n, ok := privateRequests[p.ReqCode]; ok {
			return n
		}
		return fmt.Sprintf("req_%d", p.ReqCode)
	}
	if n, ok := modeNames[p.Mode]; ok {
		return n
	}
	return "unknown"
}

// LooksLikeNTP is the strict catch-all peek: it only accepts shapes a real NTP
// scanner sends so unrelated UDP on other ports is not misrouted. Port 123
// has its own rule and uses the tolerant Parse.
func LooksLikeNTP(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	vn := int(data[0] >> 3 & 7)
	switch data[0] & 7 {
	case ModeClient:
		return len(data) == PacketLen && (vn == 3 || vn == 4)
	case ModeControl:
		if vn < 2 || vn > 4 || len(data) < ControlHeaderLen || data[1]&0x80 != 0 {
			return false
		}
		p, err := Parse(data)
		if err != nil {
			return false
		}
		_, known := controlOpcodes[p.Opcode]
		return known && len(data) >= ControlHeaderLen+p.Offset+p.Count
	case ModePrivate:
		if vn < 2 || vn > 4 || len(data) < PrivateHeaderLen || data[0]&0x80 != 0 {
			return false
		}
		// implementation: 0 universal, 2 xntpd-old, 3 xntpd
		impl := data[2]
		_, known := privateRequests[int(data[3])]
		return (impl == 0 || impl == 2 || impl == 3) && known
	}
	return false
}

// BuildResponse returns the reply for a request, or nil to stay silent. The
// reply is never larger than the request, so the sensor cannot amplify.
// Mode 3 gets a stratum 2 server packet; mode 6 and 7 requests get a small
// error reply (a modern ntpd with queries restricted); other modes get none.
// now and refID are injected so tests are deterministic.
func BuildResponse(p *Packet, req []byte, now time.Time, refID [4]byte) []byte {
	var resp []byte
	switch p.Mode {
	case ModeClient:
		resp = buildServer(p, req, now, refID)
	case ModeControl:
		if p.Response {
			return nil
		}
		resp = make([]byte, ControlHeaderLen)
		resp[0] = byte(p.LeapIndicator<<6) | byte(p.Version<<3) | ModeControl
		resp[1] = 0x80 | 0x40 | byte(p.Opcode) // response + error
		copy(resp[2:4], req[2:4])              // sequence
		binary.BigEndian.PutUint16(resp[4:6], uint16(cerrPermission)<<8)
		copy(resp[6:8], req[6:8]) // association id
	case ModePrivate:
		if p.Response {
			return nil
		}
		resp = make([]byte, PrivateHeaderLen)
		resp[0] = 0x80 | byte(p.Version<<3) | ModePrivate
		resp[1] = req[1] & 0x7f // sequence
		resp[2] = req[2]
		resp[3] = req[3]
		binary.BigEndian.PutUint16(resp[4:6], uint16(infoErrReq)<<12)
	default:
		return nil
	}
	if len(resp) > len(req) {
		return nil
	}
	return resp
}

func buildServer(p *Packet, req []byte, now time.Time, refID [4]byte) []byte {
	resp := make([]byte, PacketLen)
	vn := p.Version
	if vn < 1 || vn > 4 {
		vn = 4
	}
	resp[0] = byte(vn<<3) | ModeServer                 // LI 0: synchronized
	resp[1] = 2                                        // stratum
	resp[2] = req[2]                                   // poll echoed
	resp[3] = 0xec                                     // precision 2^-20
	binary.BigEndian.PutUint32(resp[4:8], 0x00000e1d)  // root delay (~0.055 s)
	binary.BigEndian.PutUint32(resp[8:12], 0x000007a3) // root dispersion
	copy(resp[12:16], refID[:])
	ts := toTimestamp(now)
	binary.BigEndian.PutUint64(resp[16:24], toTimestamp(now.Add(-37*time.Second))) // reference
	copy(resp[24:32], req[40:48])                                                  // origin = client transmit
	binary.BigEndian.PutUint64(resp[32:40], ts)                                    // receive
	binary.BigEndian.PutUint64(resp[40:48], toTimestamp(now.Add(120*time.Microsecond)))
	return resp
}

func toTimestamp(t time.Time) uint64 {
	secs := uint64(t.Unix()) + ntpEpochOffset
	frac := uint64(t.Nanosecond()) << 32 / 1_000_000_000
	return secs<<32 | frac
}
