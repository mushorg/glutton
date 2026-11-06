// Package wdb parses Wind River WDB (VxWorks target debug agent) RPC calls
// and builds replies. WDB is ONC RPC program 0x55555555 version 1 over
// udp/17185. After the RPC call header every request carries a parameter
// wrapper (checksum, size, sequence number); every reply carries a reply
// wrapper (checksum, size, error code) after the RPC reply header.
//
// Layout and procedure numbers follow the public WDB RPC description used by
// internet-wide scanners (the 2010 VxWorks WDB research and Metasploit's
// wdbrpc_version module); byte-exact agent fidelity is not attempted.
package wdb

import (
	"encoding/binary"
	"errors"
	"strconv"

	"github.com/mushorg/glutton/protocols/tcp/oncrpc"
)

const (
	// Program is the WDB RPC program number.
	Program = 0x55555555
	// Version is the only WDB RPC version.
	Version = 1

	ProcPing       = 0
	ProcConnect    = 1
	ProcDisconnect = 2

	// checksumMarker is the high half of a filled-in wrapper checksum word.
	checksumMarker = 0xffff0000
	// wrapperLen is the WDB parameter/reply wrapper size (three XDR words).
	wrapperLen = 12
)

// ErrShortWrapper is returned when a WDB call ends before its parameter
// wrapper.
var ErrShortWrapper = errors.New("wdb: call shorter than parameter wrapper")

var procNames = map[uint32]string{
	0:  "WDB_TARGET_PING",
	1:  "WDB_TARGET_CONNECT",
	2:  "WDB_TARGET_DISCONNECT",
	3:  "WDB_TARGET_MODE_SET",
	4:  "WDB_TARGET_MODE_GET",
	10: "WDB_MEM_READ",
	11: "WDB_MEM_WRITE",
}

// ProcName names a WDB procedure, WDB_PROC_<n> for unknown numbers.
func ProcName(proc uint32) string {
	if n, ok := procNames[proc]; ok {
		return n
	}
	return "WDB_PROC_" + strconv.FormatUint(uint64(proc), 10)
}

// Wrapper is the WDB parameter wrapper that follows the RPC call header.
type Wrapper struct {
	Checksum uint32
	Size     uint32
	Seq      uint32
	Args     []byte
}

// ParseWrapper decodes the parameter wrapper from the RPC call arguments.
func ParseWrapper(args []byte) (*Wrapper, error) {
	if len(args) < wrapperLen {
		return nil, ErrShortWrapper
	}
	return &Wrapper{
		Checksum: binary.BigEndian.Uint32(args),
		Size:     binary.BigEndian.Uint32(args[4:]),
		Seq:      binary.BigEndian.Uint32(args[8:]),
		Args:     args[wrapperLen:],
	}, nil
}

// TargetInfo is the WDB_TGT_INFO returned by WDB_TARGET_CONNECT.
type TargetInfo struct {
	AgentVersion string
	MTU          uint32
	Mode         uint32
	RTType       uint32
	RTVersion    string
	CPUType      uint32
	HasFPP       bool
	HasWP        bool
	PageSize     uint32
	Endian       uint32
	BSPName      string
	Bootline     string
	MemBase      uint32
	MemSize      uint32
	HostPoolBase uint32
	HostPoolSize uint32
}

// DefaultTarget is a VxWorks 5.5.1 PowerPC board with the agent in task mode.
// The values are plausible for a Tornado 2.2 era target; they are not copied
// from a specific device.
var DefaultTarget = TargetInfo{
	AgentVersion: "2.0",
	MTU:          1500,
	Mode:         1, // WDB_MODE_TASK
	RTType:       1, // WDB_RT_VXWORKS
	RTVersion:    "5.5.1",
	CPUType:      53, // PPC603
	HasFPP:       true,
	PageSize:     4096,
	Endian:       4321, // big endian
	BSPName:      "Wind River SBC8260",
	Bootline:     "motfcc(0,0)host:/tornado/target/config/wrSbc8260/vxWorks h=192.168.1.10 e=192.168.1.20:ffffff00 u=target tn=sbc8260",
	MemBase:      0,
	MemSize:      0x04000000,
	HostPoolBase: 0x003ff000,
	HostPoolSize: 0x00010000,
}

type encoder struct{ b []byte }

func (e *encoder) u32(v ...uint32) {
	for _, x := range v {
		e.b = binary.BigEndian.AppendUint32(e.b, x)
	}
}

func (e *encoder) boolean(v bool) {
	if v {
		e.u32(1)
		return
	}
	e.u32(0)
}

func (e *encoder) str(s string) {
	e.u32(uint32(len(s)))
	e.b = append(e.b, s...)
	for len(e.b)%4 != 0 {
		e.b = append(e.b, 0)
	}
}

const (
	msgAccepted = 0
	msgDenied   = 1

	acceptSuccess      = 0
	acceptProgUnavail  = 1
	acceptProgMismatch = 2
	acceptProcUnavail  = 3

	rejectRPCMismatch = 0
)

func accepted(xid, stat uint32) *encoder {
	e := &encoder{}
	e.u32(xid, oncrpc.MsgReply, msgAccepted, 0, 0, stat) // AUTH_NONE verifier
	return e
}

// Checksum is the 16-bit ones' complement sum used by the WDB wrappers. It
// covers the message after the XID, with the checksum word itself zeroed.
// (Derived from captured scanner calls, whose checksums verify this way.)
func Checksum(msg []byte, checksumOff int) uint16 {
	var sum uint32
	for i := 4; i+1 < len(msg); i += 2 {
		if i >= checksumOff && i < checksumOff+4 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(msg[i:]))
	}
	if len(msg)%2 == 1 {
		sum += uint32(msg[len(msg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// replyHeaderLen is the accepted RPC reply header before the WDB wrapper.
const replyHeaderLen = 24

// finish fills in the reply wrapper's checksum and size words.
func finish(b []byte) []byte {
	binary.BigEndian.PutUint32(b[replyHeaderLen+4:], uint32(len(b)-4))
	binary.BigEndian.PutUint32(b[replyHeaderLen:], checksumMarker|uint32(Checksum(b, replyHeaderLen)))
	return b
}

// Reply builds the RPC reply for a WDB call and the outcome name for the
// write frame. It returns nil for messages an agent does not answer (RPC
// replies, calls without a full header).
func Reply(c *oncrpc.Call, target TargetInfo) ([]byte, string) {
	if c == nil || c.MsgType != oncrpc.MsgCall || !c.Header {
		return nil, ""
	}
	if c.RPCVersion != 2 {
		e := &encoder{}
		e.u32(c.XID, oncrpc.MsgReply, msgDenied, rejectRPCMismatch, 2, 2)
		return e.b, "RPC_MISMATCH"
	}
	if c.Program != Program {
		return accepted(c.XID, acceptProgUnavail).b, "PROG_UNAVAIL"
	}
	if c.Version != Version {
		e := accepted(c.XID, acceptProgMismatch)
		e.u32(Version, Version)
		return e.b, "PROG_MISMATCH"
	}
	switch c.Procedure {
	case ProcPing, ProcConnect, ProcDisconnect:
	default:
		return accepted(c.XID, acceptProcUnavail).b, "PROC_UNAVAIL"
	}
	e := accepted(c.XID, acceptSuccess)
	e.u32(0, 0, 0) // wrapper checksum, size (filled in by finish), errCode OK
	if c.Procedure == ProcConnect {
		t := target
		e.str(t.AgentVersion)
		e.u32(t.MTU, t.Mode, t.RTType)
		e.str(t.RTVersion)
		e.u32(t.CPUType)
		e.boolean(t.HasFPP)
		e.boolean(t.HasWP)
		e.u32(t.PageSize, t.Endian)
		e.str(t.BSPName)
		e.str(t.Bootline)
		e.u32(t.MemBase, t.MemSize)
		e.u32(0, 0) // numRegions, empty memRegion array
		e.u32(t.HostPoolBase, t.HostPoolSize)
	}
	return finish(e.b), "SUCCESS"
}
