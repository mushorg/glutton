// Package cassandra parses and builds the framed Thrift binary-protocol
// messages that Apache Cassandra's legacy RPC interface speaks on tcp/9160.
//
// Wire format (Apache Thrift TFramedTransport + TBinaryProtocol):
//
//	frame:   uint32 length | message
//	strict:  int32 (0x8001_0000 | type) | string name | int32 seqid | struct args
//	old:     string name | byte type | int32 seqid | struct args
//	string:  int32 length | bytes
//	struct:  { byte field_type | int16 field_id | value }* | 0x00 (STOP)
package cassandra

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

// Message types.
const (
	TypeCall      uint8 = 1
	TypeReply     uint8 = 2
	TypeException uint8 = 3
	TypeOneway    uint8 = 4
)

// Thrift field types.
const (
	tStop   = 0
	tBool   = 2
	tByte   = 3
	tDouble = 4
	tI16    = 6
	tI32    = 8
	tI64    = 10
	tString = 11
	tStruct = 12
	tMap    = 13
	tSet    = 14
	tList   = 15
)

const (
	// FrameHeaderLen is the size of the TFramedTransport length prefix.
	FrameHeaderLen = 4
	// MaxFrameLen caps a frame body; larger declared lengths are rejected.
	MaxFrameLen = 64 * 1024

	strictVersionMask = 0xffff0000
	strictVersion1    = 0x80010000

	maxDepth    = 8
	maxElements = 256

	// ExceptionUnknownMethod is TApplicationException.UNKNOWN_METHOD.
	ExceptionUnknownMethod int32 = 1
)

// FrameError reports a frame length outside 1..MaxFrameLen.
type FrameError struct {
	Length uint32
}

func (e *FrameError) Error() string {
	return fmt.Sprintf("invalid thrift frame length %d", e.Length)
}

// ReadFrame reads one length-prefixed frame and returns the raw bytes
// (length prefix included). On a short read it returns what arrived along
// with the error. An invalid length returns the 4 prefix bytes and a
// *FrameError without reading the body.
func ReadFrame(r io.Reader) ([]byte, error) {
	hdr := make([]byte, FrameHeaderLen)
	n, err := io.ReadFull(r, hdr)
	if err != nil {
		return hdr[:n], err
	}
	length := binary.BigEndian.Uint32(hdr)
	if length == 0 || length > MaxFrameLen {
		return hdr, &FrameError{Length: length}
	}
	raw := make([]byte, FrameHeaderLen+int(length))
	copy(raw, hdr)
	n, err = io.ReadFull(r, raw[FrameHeaderLen:])
	if err != nil {
		return raw[:FrameHeaderLen+n], err
	}
	return raw, nil
}

// Message is a parsed Thrift message header plus its decoded argument struct.
type Message struct {
	Name   string `json:"name"`
	Type   uint8  `json:"type"`
	SeqID  int32  `json:"seqid"`
	Strict bool   `json:"strict"`
	// Args maps field id to value: strings, numbers, bools, lists, and
	// nested structs/maps as objects. Nil when the args did not decode.
	Args map[string]any `json:"args,omitempty"`
}

// TypeName returns a lowercase name for a message type.
func TypeName(t uint8) string {
	switch t {
	case TypeCall:
		return "call"
	case TypeReply:
		return "reply"
	case TypeException:
		return "exception"
	case TypeOneway:
		return "oneway"
	}
	return "type-" + strconv.Itoa(int(t))
}

var errShort = errors.New("thrift message truncated")

type reader struct {
	b        []byte
	off      int
	elements int
}

func (r *reader) next(n int) ([]byte, error) {
	if n < 0 || n > len(r.b)-r.off {
		return nil, errShort
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *reader) u8() (uint8, error) {
	b, err := r.next(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *reader) i16() (int16, error) {
	b, err := r.next(2)
	if err != nil {
		return 0, err
	}
	return int16(binary.BigEndian.Uint16(b)), nil
}

func (r *reader) i32() (int32, error) {
	b, err := r.next(4)
	if err != nil {
		return 0, err
	}
	return int32(binary.BigEndian.Uint32(b)), nil
}

func (r *reader) str() (string, error) {
	n, err := r.i32()
	if err != nil {
		return "", err
	}
	b, err := r.next(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ParseMessage parses a frame body (without the length prefix). The header
// must decode for err to be nil; argument decoding is best effort and a
// malformed argument struct only leaves Args nil.
func ParseMessage(body []byte) (Message, error) {
	r := &reader{b: body}
	var m Message
	first, err := r.i32()
	if err != nil {
		return m, err
	}
	if first < 0 {
		if uint32(first)&strictVersionMask != strictVersion1 {
			return m, fmt.Errorf("bad thrift version 0x%08x", uint32(first))
		}
		m.Strict = true
		m.Type = uint8(first)
		if m.Name, err = r.str(); err != nil {
			return m, err
		}
	} else {
		name, err := r.next(int(first))
		if err != nil {
			return m, err
		}
		m.Name = string(name)
		if m.Type, err = r.u8(); err != nil {
			return m, err
		}
	}
	if m.SeqID, err = r.i32(); err != nil {
		return m, err
	}
	if args, err := r.structValue(0); err == nil {
		m.Args = args
	}
	return m, nil
}

func (r *reader) structValue(depth int) (map[string]any, error) {
	out := map[string]any{}
	for {
		ft, err := r.u8()
		if err != nil {
			return nil, err
		}
		if ft == tStop {
			return out, nil
		}
		id, err := r.i16()
		if err != nil {
			return nil, err
		}
		v, err := r.value(ft, depth+1)
		if err != nil {
			return nil, err
		}
		out[strconv.Itoa(int(id))] = v
	}
}

func (r *reader) count() (int, error) {
	n, err := r.i32()
	if err != nil {
		return 0, err
	}
	if n < 0 || int(n) > maxElements-r.elements {
		return 0, fmt.Errorf("thrift container size %d over budget", n)
	}
	return int(n), nil
}

func (r *reader) value(t uint8, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("thrift value nested too deep")
	}
	r.elements++
	if r.elements > maxElements {
		return nil, errors.New("thrift value has too many elements")
	}
	switch t {
	case tBool:
		b, err := r.u8()
		return b != 0, err
	case tByte:
		b, err := r.u8()
		return int8(b), err
	case tI16:
		return r.i16()
	case tI32:
		return r.i32()
	case tI64:
		b, err := r.next(8)
		if err != nil {
			return nil, err
		}
		return int64(binary.BigEndian.Uint64(b)), nil
	case tDouble:
		b, err := r.next(8)
		if err != nil {
			return nil, err
		}
		f := math.Float64frombits(binary.BigEndian.Uint64(b))
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return strconv.FormatFloat(f, 'g', -1, 64), nil // JSON cannot encode these
		}
		return f, nil
	case tString:
		return r.str()
	case tStruct:
		return r.structValue(depth)
	case tMap:
		kt, err := r.u8()
		if err != nil {
			return nil, err
		}
		vt, err := r.u8()
		if err != nil {
			return nil, err
		}
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		out := make(map[string]any, n)
		for i := 0; i < n; i++ {
			k, err := r.value(kt, depth+1)
			if err != nil {
				return nil, err
			}
			v, err := r.value(vt, depth+1)
			if err != nil {
				return nil, err
			}
			out[fmt.Sprint(k)] = v
		}
		return out, nil
	case tSet, tList:
		et, err := r.u8()
		if err != nil {
			return nil, err
		}
		n, err := r.count()
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			v, err := r.value(et, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown thrift type %d", t)
}

func appendI32(b []byte, v int32) []byte {
	return binary.BigEndian.AppendUint32(b, uint32(v))
}

func appendString(b []byte, s string) []byte {
	b = appendI32(b, int32(len(s)))
	return append(b, s...)
}

func appendStringField(b []byte, id int16, s string) []byte {
	b = append(b, tString)
	b = binary.BigEndian.AppendUint16(b, uint16(id))
	return appendString(b, s)
}

// BuildMessage frames a strict binary-protocol message whose body is an
// already serialized struct (fields plus STOP).
func BuildMessage(t uint8, name string, seqid int32, fields []byte) []byte {
	msg := appendI32(nil, int32(strictVersion1|uint32(t)))
	msg = appendString(msg, name)
	msg = appendI32(msg, seqid)
	msg = append(msg, fields...)
	out := binary.BigEndian.AppendUint32(make([]byte, 0, FrameHeaderLen+len(msg)), uint32(len(msg)))
	return append(out, msg...)
}

// StringResult is a result struct whose success field (id 0) is s.
func StringResult(s string) []byte {
	return append(appendStringField(nil, 0, s), tStop)
}

// VoidResult is the empty result struct of a void method.
func VoidResult() []byte {
	return []byte{tStop}
}

// BuildReply frames a REPLY for name/seqid carrying result.
func BuildReply(name string, seqid int32, result []byte) []byte {
	return BuildMessage(TypeReply, name, seqid, result)
}

// BuildException frames a TApplicationException {1: message, 2: type}.
func BuildException(name string, seqid int32, message string, typ int32) []byte {
	fields := appendStringField(nil, 1, message)
	fields = append(fields, tI32, 0x00, 0x02)
	fields = appendI32(fields, typ)
	fields = append(fields, tStop)
	return BuildMessage(TypeException, name, seqid, fields)
}
