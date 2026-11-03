// Package sofia parses and builds frames of the Sofia protocol, the private
// control protocol of XiongMai (XMeye / NetSurveillance) DVRs on tcp/34567.
// The layout is inferred from captured traffic and public write-ups of the
// "DebugShell" abuse, not from a vendor spec.
package sofia

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	// HeaderLen is the fixed frame header size.
	HeaderLen = 20
	// Magic is the first byte of every frame.
	Magic = 0xff
	// bodyTerminator follows the JSON body and is counted in DataLen.
	bodyTerminator = "\x0a\x00"
	// retOK is the Sofia "success" return code.
	retOK = 100
	// loginMsgID is the login request; its reply carries a fresh session.
	loginMsgID = 1000
	// loginSessionID is the session handed out on login.
	loginSessionID = 2
)

var (
	// ErrBadMagic is returned when a frame does not start with Magic.
	ErrBadMagic = errors.New("sofia: bad frame magic")
	// ErrBodyTooLarge is returned when the declared body exceeds the cap.
	ErrBodyTooLarge = errors.New("sofia: body too large")
)

// Header is the 20-byte frame header (little endian).
type Header struct {
	Head        uint8  `json:"head"`
	Version     uint8  `json:"version"`
	SessionID   uint32 `json:"session_id"`
	Sequence    uint32 `json:"sequence"`
	TotalPacket uint8  `json:"total_packet"`
	CurPacket   uint8  `json:"cur_packet"`
	MsgID       uint16 `json:"msg_id"`
	DataLen     uint32 `json:"data_len"`
}

// Request is one parsed client frame.
type Request struct {
	Header   Header
	Name     string
	OprName  string
	Username string
	Password string
}

type bodyFields struct {
	Name     string `json:"Name"`
	OprName  string `json:"OprName"`
	UserName string `json:"UserName"`
	PassWord string `json:"PassWord"`
}

// ParseHeader decodes the first HeaderLen bytes of b.
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderLen {
		return h, io.ErrUnexpectedEOF
	}
	h = Header{
		Head:        b[0],
		Version:     b[1],
		SessionID:   binary.LittleEndian.Uint32(b[4:8]),
		Sequence:    binary.LittleEndian.Uint32(b[8:12]),
		TotalPacket: b[12],
		CurPacket:   b[13],
		MsgID:       binary.LittleEndian.Uint16(b[14:16]),
		DataLen:     binary.LittleEndian.Uint32(b[16:20]),
	}
	if h.Head != Magic {
		return h, ErrBadMagic
	}
	return h, nil
}

// ReadRequest reads one frame from r. raw holds every byte consumed (also on
// error) so callers can record partial frames. A body longer than maxBody is
// stored up to the cap with truncated set and ErrBodyTooLarge returned.
func ReadRequest(r io.Reader, maxBody int) (req Request, raw []byte, truncated bool, err error) {
	hdr := make([]byte, HeaderLen)
	n, err := io.ReadFull(r, hdr)
	if err != nil {
		return req, hdr[:n], false, err
	}
	raw = hdr
	if req.Header, err = ParseHeader(hdr); err != nil {
		return req, raw, false, err
	}
	want := int(req.Header.DataLen)
	if want > maxBody {
		want = maxBody
		truncated = true
	}
	body := make([]byte, want)
	n, err = io.ReadFull(r, body)
	raw = append(raw, body[:n]...)
	if err != nil {
		return req, raw, truncated, err
	}
	req.parseBody(body)
	if truncated {
		return req, raw, true, ErrBodyTooLarge
	}
	return req, raw, false, nil
}

func (r *Request) parseBody(body []byte) {
	body = bytes.TrimRight(body, "\x00\r\n\t ")
	var f bodyFields
	if json.Unmarshal(body, &f) != nil {
		return
	}
	r.Name, r.OprName, r.Username, r.Password = f.Name, f.OprName, f.UserName, f.PassWord
}

// CommandName is the leaf operation: the JSON Name, then OprName, then the
// numeric message id.
func (r Request) CommandName() string {
	switch {
	case r.Name != "":
		return r.Name
	case r.OprName != "":
		return r.OprName
	}
	return fmt.Sprintf("msg-%d", r.Header.MsgID)
}

// BuildResponse answers any request with Ret 100 (success). The reply message
// id is the request id plus one, as on real devices; a login also gets a
// session id.
func BuildResponse(req Request) []byte {
	session := req.Header.SessionID
	if req.Header.MsgID == loginMsgID {
		session = loginSessionID
	}
	fields := map[string]any{
		"Ret":       retOK,
		"SessionID": fmt.Sprintf("0x%08X", session),
	}
	if req.Name != "" {
		fields["Name"] = req.Name
	}
	body, _ := json.Marshal(fields) // map of plain values; cannot fail
	body = append(body, bodyTerminator...)

	out := make([]byte, HeaderLen, HeaderLen+len(body))
	out[0] = Magic
	binary.LittleEndian.PutUint32(out[4:8], session)
	binary.LittleEndian.PutUint32(out[8:12], req.Header.Sequence)
	binary.LittleEndian.PutUint16(out[14:16], req.Header.MsgID+1)
	binary.LittleEndian.PutUint32(out[16:20], uint32(len(body)))
	return append(out, body...)
}
