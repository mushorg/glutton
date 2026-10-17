package dahua

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// login frame from Ochi event 31fde0ba-a47b-4817-9e9a-9ed5963786b0 (tcp/37777)
var captureLogin = []byte("\xa0\x00\x00\x60\x23\x00\x00\x00admin\x00\x00\x00159753\x00\x00\x04\x01\x00\x00\x00\x00\xa1\xaaadmin&&159753\x00Random:1792259910\r\n\r\n")

func TestReadRequestLogin(t *testing.T) {
	require.Len(t, captureLogin, 67)
	req, raw, truncated, err := ReadRequest(bytes.NewReader(captureLogin), 1024)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, captureLogin, raw)
	require.True(t, req.IsLogin())
	require.Equal(t, "login", req.CommandName())
	require.Equal(t, uint32(35), req.BodyLen)
	require.Equal(t, "admin", req.Username)
	require.Equal(t, "159753", req.Password)
	require.Equal(t, "1792259910", req.Nonce)
}

func TestReadRequestLongPasswordFromBody(t *testing.T) {
	body := "admin&&averylongpassword\x00Random:1\r\n\r\n"
	frame := append(append([]byte{0xa0, 0, 0, 0x60, byte(len(body)), 0, 0, 0}, make([]byte, 24)...), body...)
	copy(frame[8:], "admin")
	copy(frame[16:], "averylon")
	req, _, _, err := ReadRequest(bytes.NewReader(frame), 1024)
	require.NoError(t, err)
	require.Equal(t, "averylongpassword", req.Password)
}

func TestReadRequestTruncatedHeader(t *testing.T) {
	_, raw, _, err := ReadRequest(bytes.NewReader(captureLogin[:10]), 1024)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, captureLogin[:10], raw)
}

func TestReadRequestOversizeBody(t *testing.T) {
	frame := append([]byte{0xa0, 0, 0, 0, 0xff, 0xff, 0, 0}, make([]byte, 24)...)
	frame = append(frame, make([]byte, 0xffff)...)
	req, raw, truncated, err := ReadRequest(bytes.NewReader(frame), 100)
	require.ErrorIs(t, err, ErrBodyTooLarge)
	require.True(t, truncated)
	require.Len(t, raw, HeaderLen+100)
	require.Equal(t, uint32(0xffff), req.BodyLen)
}

func TestUnknownCommandName(t *testing.T) {
	require.Equal(t, "cmd-0xf1", Request{Command: 0xf1}.CommandName())
}

func TestBuildLoginResponse(t *testing.T) {
	resp := BuildLoginResponse(StatusWrongPassword)
	require.Len(t, resp, HeaderLen)
	require.Equal(t, CmdLoginResponse, resp[0])
	require.Equal(t, StatusWrongPassword, resp[8])
}
