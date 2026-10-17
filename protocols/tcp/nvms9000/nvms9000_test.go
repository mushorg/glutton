package nvms9000

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const capturedXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<request version=\"1.0\" systemType=\"NVMS-9000\" clientType=\"WEB\"/>\n"

// capturedHeader is the first 24 bytes of the request seen on tcp/8888
// (Ochi event 8c21d002-4069-4f48-a464-ac3eb5742229, 256 bytes in all).
const capturedHeader = "31313131f800000004000001" + "1b09000002010000" + "e8000000"

func pad(s string) []byte {
	return append([]byte(s), make([]byte, 64-len(s))...)
}

func capturedRequest(t *testing.T) []byte {
	t.Helper()
	hdr, err := hex.DecodeString(capturedHeader)
	require.NoError(t, err)
	body := append(pad("admin"), pad("queryBasicCfg")...)
	body = append(body, capturedXML...)
	return append(hdr, body...)
}

func TestReadFrameCaptured(t *testing.T) {
	raw := capturedRequest(t)
	require.Len(t, raw, 256)

	frame, got, err := ReadFrame(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Equal(t, raw, got)
	require.Equal(t, Header{Version: 0x01000004, Command: 0x091b, Unknown: 0x0102, BodyLen: 232}, frame.Header)
	require.Len(t, frame.Body, 232)

	req := ParseRequest(frame.Body)
	require.Equal(t, "admin", req.Username)
	require.Equal(t, "queryBasicCfg", req.Operation)
	require.Equal(t, strings.TrimSpace(capturedXML), req.XML)
}

func TestBuildRoundTrip(t *testing.T) {
	raw := capturedRequest(t)
	frame, _, err := ReadFrame(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Equal(t, raw, Build(frame.Header, frame.Body))
}

func TestLooksLikeNVMS(t *testing.T) {
	require.True(t, LooksLikeNVMS(capturedRequest(t)[:PeekLen]))
	require.False(t, LooksLikeNVMS([]byte("1111")))
	require.False(t, LooksLikeNVMS([]byte("GET / HTTP/1.1")))
	// text that happens to start with the magic: length 0x31313131 is huge
	require.False(t, LooksLikeNVMS([]byte("11111111")))
	// below the inner header size
	require.False(t, LooksLikeNVMS([]byte("1111\x04\x00\x00\x00")))
}

func TestReadFrameErrors(t *testing.T) {
	_, raw, err := ReadFrame(bytes.NewReader([]byte("GET / HT")))
	require.ErrorIs(t, err, ErrBadMagic)
	require.Equal(t, []byte("GET / HT"), raw)

	_, _, err = ReadFrame(bytes.NewReader([]byte("1111\x04\x00\x00\x00")))
	require.ErrorIs(t, err, ErrBadLen)

	_, _, err = ReadFrame(bytes.NewReader([]byte("1111\xff\xff\xff\x00")))
	require.ErrorIs(t, err, ErrTooLarge)

	short := capturedRequest(t)[:100]
	_, raw, err = ReadFrame(bytes.NewReader(short))
	require.Error(t, err)
	require.Equal(t, short, raw)
}

func TestParseRequestBareXML(t *testing.T) {
	req := ParseRequest([]byte(capturedXML))
	require.Empty(t, req.Operation)
	require.Equal(t, strings.TrimSpace(capturedXML), req.XML)
}

func TestCredentials(t *testing.T) {
	user, pass := Credentials(`<request><content><userName><![CDATA[root]]></userName><password><![CDATA[xc3511]]></password></content></request>`)
	require.Equal(t, "root", user)
	require.Equal(t, "xc3511", pass)

	user, pass = Credentials(`<userName>a&amp;b</userName><password>x</password>`)
	require.Equal(t, "a&b", user)
	require.Equal(t, "x", pass)

	user, pass = Credentials(capturedXML)
	require.Empty(t, user)
	require.Empty(t, pass)
}

func TestRandomIdentityVaries(t *testing.T) {
	a, b := RandomIdentity(), RandomIdentity()
	require.NotEqual(t, a.Serial, b.Serial)
	require.NotEqual(t, a.MAC, b.MAC)
	require.Regexp(t, `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`, a.MAC)
}

func TestReplyXML(t *testing.T) {
	id := Identity{Name: "NVR", Model: "M", Firmware: "1.0", Serial: "S1", MAC: "00:11:22:33:44:55"}
	xml := BasicCfgXML(id)
	require.Contains(t, xml, `status="success"`)
	require.Contains(t, xml, "<![CDATA[S1]]>")
	require.Contains(t, xml, "00:11:22:33:44:55")
	require.Contains(t, FailXML(), `status="fail"`)
	require.NotContains(t, strings.ToLower(xml+FailXML()), "glutton")
}
