package mongodb

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
)

// Wire-protocol opcodes (MongoDB spec).
const (
	OpReply       int32 = 1
	OpUpdate      int32 = 2001
	OpInsert      int32 = 2002
	OpQuery       int32 = 2004
	OpGetMore     int32 = 2005
	OpDelete      int32 = 2006
	OpKillCursors int32 = 2007
	OpCompressed  int32 = 2012
	OpMsg         int32 = 2013
)

const (
	headerLen          = 16
	fakeMongoVersion   = "7.0.0"
	fakeMaxWireVersion = int32(17)
	fakeMinWireVersion = int32(0)
)

// Header is the 16-byte MongoDB message header.
type Header struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

// CommandName returns the first non-$ BSON field in an OP_QUERY or OP_MSG body.
func CommandName(opcode int32, msg []byte) string {
	if len(msg) < headerLen {
		return ""
	}
	switch opcode {
	case OpQuery:
		return commandFromOpQuery(msg)
	case OpMsg:
		return commandFromOpMsg(msg)
	default:
		return ""
	}
}

func commandFromOpQuery(msg []byte) string {
	off := headerLen
	if off+4 > len(msg) {
		return ""
	}
	off += 4 // flags
	nul := bytes.IndexByte(msg[off:], 0)
	if nul < 0 {
		return ""
	}
	off += nul + 1
	if off+8 > len(msg) {
		return ""
	}
	off += 8 // numberToSkip, numberToReturn
	return firstElementName(msg[off:])
}

func commandFromOpMsg(msg []byte) string {
	off := headerLen
	if off+4 > len(msg) {
		return ""
	}
	off += 4 // flagBits
	for off < len(msg) {
		kind := msg[off]
		off++
		switch kind {
		case 0:
			return firstElementName(msg[off:])
		case 1:
			if off+4 > len(msg) {
				return ""
			}
			size := int(binary.LittleEndian.Uint32(msg[off:]))
			if size < 4 || off+size > len(msg) {
				return ""
			}
			off += size
		default:
			return ""
		}
	}
	return ""
}

func firstElementName(doc []byte) string {
	if len(doc) < 6 {
		return ""
	}
	size := int(binary.LittleEndian.Uint32(doc[:4]))
	if size < 5 || size > len(doc) {
		return ""
	}
	// type byte at doc[4], then cstring field name
	nameEnd := bytes.IndexByte(doc[5:size], 0)
	if nameEnd < 0 {
		return ""
	}
	return string(doc[5 : 5+nameEnd])
}

func replyDocument(command string) []byte {
	switch strings.ToLower(command) {
	case "hello", "ismaster":
		return handshakeDoc()
	case "buildinfo":
		return buildInfoDoc()
	default:
		return okDoc()
	}
}

func handshakeDoc() []byte {
	return bsonDoc(
		bsonBool("ismaster", true),
		bsonBool("isWritablePrimary", true),
		bsonInt32("maxWireVersion", fakeMaxWireVersion),
		bsonInt32("minWireVersion", fakeMinWireVersion),
		bsonDouble("ok", 1),
	)
}

func buildInfoDoc() []byte {
	return bsonDoc(
		bsonString("version", fakeMongoVersion),
		bsonInt32Array("versionArray", []int32{7, 0, 0, 0}),
		bsonDouble("ok", 1),
	)
}

func okDoc() []byte {
	return bsonDoc(bsonDouble("ok", 1))
}

// BuildResponse answers OP_QUERY with OP_REPLY and everything else with OP_MSG.
func BuildResponse(req Header, command string) (Header, []byte, error) {
	doc := replyDocument(command)
	switch req.OpCode {
	case OpQuery:
		return encodeOpReply(req, doc)
	default:
		return encodeOpMsg(req, doc)
	}
}

func encodeOpMsg(req Header, doc []byte) (Header, []byte, error) {
	body := new(bytes.Buffer)
	if err := binary.Write(body, binary.LittleEndian, uint32(0)); err != nil {
		return Header{}, nil, err
	}
	if err := body.WriteByte(0); err != nil {
		return Header{}, nil, err
	}
	if _, err := body.Write(doc); err != nil {
		return Header{}, nil, err
	}
	return encodeMessage(req, OpMsg, body.Bytes())
}

func encodeOpReply(req Header, doc []byte) (Header, []byte, error) {
	body := new(bytes.Buffer)
	if err := binary.Write(body, binary.LittleEndian, int32(0)); err != nil {
		return Header{}, nil, err
	}
	if err := binary.Write(body, binary.LittleEndian, int64(0)); err != nil {
		return Header{}, nil, err
	}
	if err := binary.Write(body, binary.LittleEndian, int32(0)); err != nil {
		return Header{}, nil, err
	}
	if err := binary.Write(body, binary.LittleEndian, int32(1)); err != nil {
		return Header{}, nil, err
	}
	if _, err := body.Write(doc); err != nil {
		return Header{}, nil, err
	}
	return encodeMessage(req, OpReply, body.Bytes())
}

func encodeMessage(req Header, opCode int32, body []byte) (Header, []byte, error) {
	hdr := Header{
		MessageLength: int32(headerLen + len(body)),
		RequestID:     req.RequestID + 1,
		ResponseTo:    req.RequestID,
		OpCode:        opCode,
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, hdr); err != nil {
		return hdr, nil, err
	}
	if _, err := buf.Write(body); err != nil {
		return hdr, nil, err
	}
	return hdr, buf.Bytes(), nil
}

func bsonDoc(elems ...[]byte) []byte {
	var inner []byte
	for _, e := range elems {
		inner = append(inner, e...)
	}
	size := 4 + len(inner) + 1
	buf := make([]byte, 4, size)
	binary.LittleEndian.PutUint32(buf, uint32(size))
	buf = append(buf, inner...)
	return append(buf, 0)
}

func bsonDouble(name string, v float64) []byte {
	b := append([]byte{0x01}, append([]byte(name), 0)...)
	var bits [8]byte
	binary.LittleEndian.PutUint64(bits[:], math.Float64bits(v))
	return append(b, bits[:]...)
}

func bsonBool(name string, v bool) []byte {
	b := append([]byte{0x08}, append([]byte(name), 0)...)
	if v {
		return append(b, 1)
	}
	return append(b, 0)
}

func bsonInt32(name string, v int32) []byte {
	b := append([]byte{0x10}, append([]byte(name), 0)...)
	var bits [4]byte
	binary.LittleEndian.PutUint32(bits[:], uint32(v))
	return append(b, bits[:]...)
}

func bsonString(name, v string) []byte {
	b := append([]byte{0x02}, append([]byte(name), 0)...)
	var lenb [4]byte
	binary.LittleEndian.PutUint32(lenb[:], uint32(len(v)+1))
	b = append(b, lenb[:]...)
	return append(b, append([]byte(v), 0)...)
}

func bsonInt32Array(name string, vals []int32) []byte {
	elems := make([][]byte, len(vals))
	for i, v := range vals {
		elems[i] = bsonInt32(itoa(i), v)
	}
	inner := bsonDoc(elems...)
	b := append([]byte{0x04}, append([]byte(name), 0)...)
	return append(b, inner...)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// WrapOpQuery builds a client OP_QUERY for tests and capture replay.
func WrapOpQuery(requestID int32, collection string, query []byte) []byte {
	body := new(bytes.Buffer)
	_ = binary.Write(body, binary.LittleEndian, int32(0))
	_, _ = body.Write(append([]byte(collection), 0))
	_ = binary.Write(body, binary.LittleEndian, int32(0))
	_ = binary.Write(body, binary.LittleEndian, int32(-1))
	_, _ = body.Write(query)
	hdr := Header{RequestID: requestID, OpCode: OpQuery}
	_, msg, _ := encodeMessage(hdr, OpQuery, body.Bytes())
	return msg
}

// WrapOpMsg builds a client OP_MSG (kind-0 body) for tests and capture replay.
func WrapOpMsg(requestID int32, doc []byte) []byte {
	body := new(bytes.Buffer)
	_ = binary.Write(body, binary.LittleEndian, uint32(0))
	_ = body.WriteByte(0)
	_, _ = body.Write(doc)
	hdr := Header{RequestID: requestID, OpCode: OpMsg}
	_, msg, _ := encodeMessage(hdr, OpMsg, body.Bytes())
	return msg
}

// CmdDoc is a BSON document whose first field is command: 1.0 plus optional extra elements.
func CmdDoc(command string, extra ...[]byte) []byte {
	elems := [][]byte{bsonDouble(command, 1)}
	elems = append(elems, extra...)
	return bsonDoc(elems...)
}

// StringField is a BSON string element for CmdDoc extras (e.g. $db).
func StringField(name, value string) []byte {
	return bsonString(name, value)
}
