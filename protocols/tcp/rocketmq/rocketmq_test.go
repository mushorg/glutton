package rocketmq

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Captured probe on tcp/10911 and tcp/13911 (run-1794154414-1.jsonl events 3 and 5).
var capturedRuntimeInfo = append([]byte{0, 0, 0, 0x64, 0, 0, 0, 0x60},
	`{"code":28,"flag":0,"language":"JAVA","opaque":0,"serializeTypeCurrentRPC":"JSON","version":433}`...)

func fixedBroker() *Broker {
	b := NewBroker()
	now := time.Date(2026, 11, 8, 16, 0, 0, 0, time.UTC)
	b.Now = func() time.Time { return now }
	return b
}

func TestReadFrameCaptured(t *testing.T) {
	f, err := ReadFrame(bytes.NewReader(capturedRuntimeInfo))
	require.NoError(t, err)
	require.Equal(t, capturedRuntimeInfo, f.Raw)
	require.Equal(t, byte(SerializeJSON), f.SerializeType)
	require.Equal(t, Header{Code: 28, Language: "JAVA", SerializeTypeCurrentRPC: "JSON", Version: 433}, f.Header)
	require.Empty(t, f.Body)
	require.Equal(t, "GET_BROKER_RUNTIME_INFO", RequestName(f.Header.Code))
}

func TestEncodeRoundTrip(t *testing.T) {
	h := Header{Code: 25, Language: "JAVA", Opaque: 7, SerializeTypeCurrentRPC: "JSON", Version: 433}
	raw := Encode(h, []byte("a=b\n"))
	f, err := ReadFrame(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Equal(t, h, f.Header)
	require.Equal(t, []byte("a=b\n"), f.Body)
}

func TestReplyRuntimeInfo(t *testing.T) {
	f, err := ReadFrame(bytes.NewReader(capturedRuntimeInfo))
	require.NoError(t, err)
	reply, code, ok := fixedBroker().Reply(f)
	require.True(t, ok)
	require.Equal(t, CodeSuccess, code)
	rf, err := ReadFrame(bytes.NewReader(reply))
	require.NoError(t, err)
	require.Equal(t, Header{Code: 0, Flag: FlagResponse, Language: "JAVA", SerializeTypeCurrentRPC: "JSON", Version: 413}, rf.Header)
	var body struct {
		Table map[string]string `json:"table"`
	}
	require.NoError(t, json.Unmarshal(rf.Body, &body))
	require.Equal(t, "V4_9_4", body.Table["brokerVersionDesc"])
	require.Equal(t, "413", body.Table["brokerVersion"])
	require.Equal(t, "[ 3 days, 1 hours, 0 minutes, 0 seconds ]", body.Table["runtime"])
}

func TestReplyBrokerConfig(t *testing.T) {
	reply, code, ok := fixedBroker().Reply(Frame{Header: Header{Code: CodeGetBrokerConf, Opaque: 9}})
	require.True(t, ok)
	require.Equal(t, CodeSuccess, code)
	rf, err := ReadFrame(bytes.NewReader(reply))
	require.NoError(t, err)
	require.Equal(t, "broker-a", ParseProperties(rf.Body)["brokerName"])
}

func TestReplyEchoesOpaqueAndUnsupported(t *testing.T) {
	req := Frame{Header: Header{Code: 999, Opaque: 42}}
	reply, code, ok := fixedBroker().Reply(req)
	require.True(t, ok)
	require.Equal(t, CodeNotSupported, code)
	rf, err := ReadFrame(bytes.NewReader(reply))
	require.NoError(t, err)
	require.Equal(t, int32(42), rf.Header.Opaque)
	require.Equal(t, " request type 999 not supported", rf.Header.Remark)
	require.Equal(t, "REQUEST_CODE_NOT_SUPPORTED", ResponseName(code))
}

func TestReplyOnewayAndResponse(t *testing.T) {
	_, _, ok := fixedBroker().Reply(Frame{Header: Header{Code: 34, Flag: FlagOneway}})
	require.False(t, ok)
	_, _, ok = fixedBroker().Reply(Frame{Header: Header{Code: 0, Flag: FlagResponse}})
	require.False(t, ok)
}

func TestReadFrameBinaryHeader(t *testing.T) {
	var hdr bytes.Buffer
	_ = binary.Write(&hdr, binary.BigEndian, int16(28))
	hdr.WriteByte(0) // JAVA
	_ = binary.Write(&hdr, binary.BigEndian, int16(433))
	_ = binary.Write(&hdr, binary.BigEndian, int32(5))
	_ = binary.Write(&hdr, binary.BigEndian, int32(0))
	_ = binary.Write(&hdr, binary.BigEndian, int32(0)) // empty remark
	var ext bytes.Buffer
	_ = binary.Write(&ext, binary.BigEndian, int16(1))
	ext.WriteString("k")
	_ = binary.Write(&ext, binary.BigEndian, int32(1))
	ext.WriteString("v")
	_ = binary.Write(&hdr, binary.BigEndian, int32(ext.Len()))
	hdr.Write(ext.Bytes())

	raw := make([]byte, 8)
	binary.BigEndian.PutUint32(raw[0:4], uint32(4+hdr.Len()))
	binary.BigEndian.PutUint32(raw[4:8], uint32(SerializeRocketMQ)<<24|uint32(hdr.Len()))
	raw = append(raw, hdr.Bytes()...)

	f, err := ReadFrame(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Equal(t, Header{Code: 28, Language: "JAVA", Version: 433, Opaque: 5, SerializeTypeCurrentRPC: "ROCKETMQ", ExtFields: map[string]string{"k": "v"}}, f.Header)
}

func TestReadFrameMalformed(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{0x7f, 0, 0, 0}))
	require.True(t, errors.Is(err, ErrTooLarge))
	require.True(t, errors.Is(err, ErrMalformed))

	_, err = ReadFrame(bytes.NewReader([]byte{0, 0, 0, 2, 0, 0}))
	require.True(t, errors.Is(err, ErrBadLength))

	_, err = ReadFrame(bytes.NewReader([]byte{0, 0, 0, 6, 0, 0, 0, 2, '{', 'x'}))
	require.True(t, errors.Is(err, ErrMalformed))

	_, err = ReadFrame(bytes.NewReader([]byte{0, 0, 0, 4, 9, 0, 0, 0}))
	require.True(t, errors.Is(err, ErrMalformed))
}

func TestParseProperties(t *testing.T) {
	got := ParseProperties([]byte("# c\nfilterServerNums=1\nrocketmqHome = /tmp\n\nbad\n"))
	require.Equal(t, map[string]string{"filterServerNums": "1", "rocketmqHome": "/tmp"}, got)
	require.Nil(t, ParseProperties(nil))
}
