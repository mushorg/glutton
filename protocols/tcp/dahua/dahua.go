// Package dahua parses and builds the Dahua DVR/NVR private protocol
// ("DVRIP", tcp/37777): a 32-byte header followed by a body. The layout is
// inferred from captured login frames, not from a published spec: byte 0 is the
// command, bytes 4-7 the little-endian body length, bytes 8-15 and 16-23 the
// NUL-padded username and password, and the login body repeats them as
// "user&&pass\x00Random:<nonce>\r\n\r\n".
package dahua

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// HeaderLen is the fixed header size.
	HeaderLen = 32

	// CmdLogin is the first byte of a login request.
	CmdLogin byte = 0xa0
	// CmdLoginResponse is the first byte of a login response.
	CmdLoginResponse byte = 0xb0

	// StatusWrongPassword is written at header offset 8 of a login response.
	// Unverified against a real device; it is the value commonly documented for
	// a rejected password.
	StatusWrongPassword byte = 0x01

	loginCommandName = "login"
)

var (
	// ErrBodyTooLarge means the announced body exceeds the capture cap.
	ErrBodyTooLarge = errors.New("dahua: body too large")
)

// Request is one parsed client frame.
type Request struct {
	Command  byte
	BodyLen  uint32
	Username string
	Password string
	Nonce    string
}

// CommandName is the leaf operation for a frame.
func (r Request) CommandName() string {
	if r.Command == CmdLogin {
		return loginCommandName
	}
	return fmt.Sprintf("cmd-0x%02x", r.Command)
}

// IsLogin reports whether the frame is a login request.
func (r Request) IsLogin() bool { return r.Command == CmdLogin }

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// ReadRequest reads one header plus body. raw holds the bytes consumed so far
// even on error, so a partial frame can still be recorded. A body longer than
// maxBody is read up to the cap, returned truncated, with ErrBodyTooLarge.
func ReadRequest(r io.Reader, maxBody int) (req Request, raw []byte, truncated bool, err error) {
	header := make([]byte, HeaderLen)
	n, err := io.ReadFull(r, header)
	if err != nil {
		return req, header[:n], false, err
	}
	raw = header
	req.Command = header[0]
	req.BodyLen = binary.LittleEndian.Uint32(header[4:8])
	req.Username = cstring(header[8:16])
	req.Password = cstring(header[16:24])

	bodyLen := int64(req.BodyLen)
	toRead := bodyLen
	if toRead > int64(maxBody) {
		toRead = int64(maxBody)
		truncated = true
	}
	body := make([]byte, toRead)
	n, err = io.ReadFull(r, body)
	raw = append(raw, body[:n]...)
	if err != nil {
		return req, raw, truncated, err
	}
	if truncated {
		return req, raw, true, ErrBodyTooLarge
	}
	parseBody(&req, body)
	return req, raw, false, nil
}

// parseBody extracts the full credentials and the nonce from a login body. The
// header fields hold only 8 bytes, so a longer password is only complete here.
func parseBody(req *Request, body []byte) {
	text := cstring(body)
	if user, pass, ok := strings.Cut(text, "&&"); ok {
		req.Username, req.Password = user, pass
	}
	if _, rest, ok := strings.Cut(string(body), "Random:"); ok {
		if end := strings.IndexAny(rest, "\r\n\x00"); end >= 0 {
			rest = rest[:end]
		}
		req.Nonce = rest
	}
}

// BuildLoginResponse returns a 32-byte login response that rejects the login.
// The layout is a best-effort guess: response command, empty body, status at
// offset 8.
func BuildLoginResponse(status byte) []byte {
	resp := make([]byte, HeaderLen)
	resp[0] = CmdLoginResponse
	resp[8] = status
	return resp
}
