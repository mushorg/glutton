// Package itp parses Interoperable Teleoperation Protocol (ITP) datagrams as
// sent by a telesurgery master console to a slave robot (udp/36000), and
// builds the slave's status reply. Layouts follow the 2009 ITP Plugfest
// description (v0.43) and the UW BioRobotics Raven II
// include/itp_teleoperation.h (LGPL); only the struct layouts are used here.
//
// ITP is little-endian packed C structs: the master sends u_struct, the slave
// answers with v_struct. There is no framing besides the datagram size.
package itp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Port is the UDP port the Raven II slave listens on.
const Port = 36000

// Datagram sizes.
const (
	SizeV043   = 84  // u_struct with integer orientation increments
	SizeRaven2 = 124 // u_struct with quaternion orientation (doubles)
	SizeV      = 52  // v_struct
)

// Layout names recorded in the decoded frame.
const (
	LayoutV043   = "v0.43"
	LayoutRaven2 = "raven2"
)

// Surgeon modes.
const (
	SurgeonDisengaged = 0
	SurgeonEngaged    = 1
)

// Slave runlevels (Raven II defines.h RL_*).
const (
	RunlevelEStop  = 0
	RunlevelInit   = 1
	RunlevelPedalU = 2
	RunlevelPedalD = 3
)

// Sequence classes, in the order the Raven II network layer tests them.
const (
	SeqReflect    = "reflect"         // sequence 0: reflect packet to sender
	SeqNew        = "new"             // first packet of a stream
	SeqValid      = "valid"           // last+1
	SeqSkipped    = "skipped"         // jumped ahead, packets dropped
	SeqDuplicate  = "duplicate"       // repeated
	SeqReset      = "reset"           // more than 1000 back
	SeqOutOfOrder = "out_of_sequence" // anything else behind
)

var ErrSize = errors.New("itp: datagram is not a u_struct")

var runlevelNames = map[int32]string{
	RunlevelEStop:  "E_STOP",
	RunlevelInit:   "INIT",
	RunlevelPedalU: "PEDAL_UP",
	RunlevelPedalD: "PEDAL_DN",
}

// RunlevelName returns the RL_* name of a runlevel.
func RunlevelName(rl int32) string {
	if name, ok := runlevelNames[rl]; ok {
		return name
	}
	return fmt.Sprintf("RL_%d", rl)
}

// U is a master-to-slave u_struct. Orientation is DelYaw/DelPitch/DelRoll in
// the v0.43 layout and Qx/Qy/Qz/Qw in the Raven II layout.
type U struct {
	Layout      string
	Sequence    uint32
	PacTyp      uint32
	Version     uint32
	DelX        [2]int32
	DelY        [2]int32
	DelZ        [2]int32
	DelYaw      [2]int32
	DelPitch    [2]int32
	DelRoll     [2]int32
	Qx          [2]float64
	Qy          [2]float64
	Qz          [2]float64
	Qw          [2]float64
	ButtonState [2]int32
	Grasp       [2]int32
	SurgeonMode int32
	Checksum    int32
}

type reader struct {
	b   []byte
	off int
}

func (r *reader) u32() uint32 {
	v := binary.LittleEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *reader) i32() int32 { return int32(r.u32()) }

func (r *reader) pair() [2]int32 { return [2]int32{r.i32(), r.i32()} }

func (r *reader) f64pair() [2]float64 {
	a := math.Float64frombits(binary.LittleEndian.Uint64(r.b[r.off:]))
	b := math.Float64frombits(binary.LittleEndian.Uint64(r.b[r.off+8:]))
	r.off += 16
	return [2]float64{a, b}
}

// Parse decodes a u_struct. The layout is chosen by size; any other size is
// rejected, as the Raven II slave drops datagrams that are not sizeof(u_struct).
func Parse(data []byte) (*U, error) {
	if len(data) != SizeV043 && len(data) != SizeRaven2 {
		return nil, ErrSize
	}
	r := &reader{b: data}
	u := &U{Sequence: r.u32(), PacTyp: r.u32(), Version: r.u32()}
	u.DelX, u.DelY, u.DelZ = r.pair(), r.pair(), r.pair()
	if len(data) == SizeRaven2 {
		u.Layout = LayoutRaven2
		u.Qx, u.Qy, u.Qz, u.Qw = r.f64pair(), r.f64pair(), r.f64pair(), r.f64pair()
	} else {
		u.Layout = LayoutV043
		u.DelYaw, u.DelPitch, u.DelRoll = r.pair(), r.pair(), r.pair()
	}
	u.ButtonState, u.Grasp = r.pair(), r.pair()
	u.SurgeonMode, u.Checksum = r.i32(), r.i32()
	return u, nil
}

// ExpectedChecksum is the Raven II UDPChecksum: surgeon mode, position
// increments, buttons and sequence, with int wraparound.
func (u *U) ExpectedChecksum() int32 {
	chk := u.SurgeonMode
	for i := 0; i < 2; i++ {
		chk += u.DelX[i] + u.DelY[i] + u.DelZ[i]
	}
	chk += u.ButtonState[0] + u.ButtonState[1]
	chk += int32(u.Sequence)
	return chk
}

// Marshal encodes u in its layout (v0.43 unless Layout is LayoutRaven2).
// Checksum is written as is.
func (u *U) Marshal() []byte {
	size := SizeV043
	if u.Layout == LayoutRaven2 {
		size = SizeRaven2
	}
	b := make([]byte, 0, size)
	le := binary.LittleEndian
	pair := func(p [2]int32) {
		b = le.AppendUint32(b, uint32(p[0]))
		b = le.AppendUint32(b, uint32(p[1]))
	}
	f64pair := func(p [2]float64) {
		b = le.AppendUint64(b, math.Float64bits(p[0]))
		b = le.AppendUint64(b, math.Float64bits(p[1]))
	}
	b = le.AppendUint32(b, u.Sequence)
	b = le.AppendUint32(b, u.PacTyp)
	b = le.AppendUint32(b, u.Version)
	pair(u.DelX)
	pair(u.DelY)
	pair(u.DelZ)
	if size == SizeRaven2 {
		f64pair(u.Qx)
		f64pair(u.Qy)
		f64pair(u.Qz)
		f64pair(u.Qw)
	} else {
		pair(u.DelYaw)
		pair(u.DelPitch)
		pair(u.DelRoll)
	}
	pair(u.ButtonState)
	pair(u.Grasp)
	b = le.AppendUint32(b, uint32(u.SurgeonMode))
	b = le.AppendUint32(b, uint32(u.Checksum))
	return b
}

// V is a slave-to-master v_struct.
type V struct {
	Sequence     uint32
	LastSequence uint32
	PacTyp       uint32
	Version      uint32
	Fx           [2]int32
	Fy           [2]int32
	Fz           [2]int32
	Runlevel     int32
	JointFlags   uint32
	Checksum     int32
}

// VChecksum mirrors UDPChecksum for the reply: runlevel, forces and sequence.
// Raven II leaves the v_struct checksum unset; this is our own convention.
func (v *V) VChecksum() int32 {
	chk := v.Runlevel
	for i := 0; i < 2; i++ {
		chk += v.Fx[i] + v.Fy[i] + v.Fz[i]
	}
	chk += int32(v.Sequence)
	return chk
}

// Marshal encodes v. Checksum is written as is.
func (v *V) Marshal() []byte {
	b := make([]byte, 0, SizeV)
	le := binary.LittleEndian
	b = le.AppendUint32(b, v.Sequence)
	b = le.AppendUint32(b, v.LastSequence)
	b = le.AppendUint32(b, v.PacTyp)
	b = le.AppendUint32(b, v.Version)
	for _, p := range [][2]int32{v.Fx, v.Fy, v.Fz} {
		b = le.AppendUint32(b, uint32(p[0]))
		b = le.AppendUint32(b, uint32(p[1]))
	}
	b = le.AppendUint32(b, uint32(v.Runlevel))
	b = le.AppendUint32(b, v.JointFlags)
	b = le.AppendUint32(b, uint32(v.Checksum))
	return b
}

// ParseV decodes a v_struct.
func ParseV(data []byte) (*V, error) {
	if len(data) != SizeV {
		return nil, ErrSize
	}
	r := &reader{b: data}
	v := &V{Sequence: r.u32(), LastSequence: r.u32(), PacTyp: r.u32(), Version: r.u32()}
	v.Fx, v.Fy, v.Fz = r.pair(), r.pair(), r.pair()
	v.Runlevel, v.JointFlags, v.Checksum = r.i32(), r.u32(), r.i32()
	return v, nil
}

// BuildReply returns the slave's v_struct for u. seq is the slave's own
// sequence number. The slave reports PEDAL_DN while the surgeon is engaged and
// PEDAL_UP otherwise, with no force feedback and no joint limits hit.
func BuildReply(u *U, seq uint32) *V {
	v := &V{
		Sequence:     seq,
		LastSequence: u.Sequence,
		PacTyp:       u.PacTyp,
		Version:      u.Version,
		Runlevel:     RunlevelPedalU,
	}
	if u.SurgeonMode == SurgeonEngaged {
		v.Runlevel = RunlevelPedalD
	}
	v.Checksum = v.VChecksum()
	return v
}

// Classify reports how cur relates to the last accepted sequence number of a
// stream and the new last value, following the Raven II network layer. seen
// is false for the first packet of a stream.
func Classify(last uint32, seen bool, cur uint32) (string, uint32) {
	switch {
	case cur == 0:
		return SeqReflect, last
	case !seen:
		return SeqNew, cur
	case uint64(cur) > uint64(last)+1:
		return SeqSkipped, cur
	case cur == last:
		return SeqDuplicate, last
	case cur > last:
		return SeqValid, cur
	case last > 1000 && cur < last-1000:
		return SeqReset, cur
	default:
		return SeqOutOfOrder, last
	}
}
