// Package rocketmq parses Apache RocketMQ remoting frames and builds broker
// replies. Layout (RemotingCommand.encode): a big-endian uint32 total length
// (everything after this field), a uint32 whose high byte is the serialize type
// (0 = JSON, 1 = ROCKETMQ binary) and whose low 24 bits are the header length,
// the header, then the body.
package rocketmq

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SerializeJSON     = 0
	SerializeRocketMQ = 1

	// FlagResponse is RPC_TYPE bit 0 of flag; FlagOneway is bit 1.
	FlagResponse = 1
	FlagOneway   = 2

	// MaxFrame caps the total length the handler accepts.
	MaxFrame = 256 * 1024

	CodeSuccess           = 0
	CodeSystemError       = 1
	CodeNotSupported      = 3
	CodeGetBrokerRuntime  = 28
	CodeUpdateBrokerConf  = 25
	CodeGetBrokerConf     = 26
	CodeHeartBeat         = 34
	CodeUnregisterClient  = 35
	CodeUpdateNamesrvConf = 318
	CodeGetNamesrvConf    = 319
)

var (
	// ErrMalformed wraps every parse failure (as opposed to I/O errors).
	ErrMalformed = errors.New("rocketmq: malformed frame")
	ErrTooLarge  = fmt.Errorf("%w: frame too large", ErrMalformed)
	ErrBadLength = fmt.Errorf("%w: bad length", ErrMalformed)
)

// requestCodes names the RequestCode constants seen in scans and exploits.
var requestCodes = map[int]string{
	10:  "SEND_MESSAGE",
	11:  "PULL_MESSAGE",
	12:  "QUERY_MESSAGE",
	17:  "UPDATE_AND_CREATE_TOPIC",
	21:  "GET_ALL_TOPIC_CONFIG",
	25:  "UPDATE_BROKER_CONFIG",
	26:  "GET_BROKER_CONFIG",
	28:  "GET_BROKER_RUNTIME_INFO",
	34:  "HEART_BEAT",
	35:  "UNREGISTER_CLIENT",
	38:  "GET_CONSUMER_LIST_BY_GROUP",
	105: "GET_ROUTEINFO_BY_TOPIC",
	106: "GET_BROKER_CLUSTER_INFO",
	206: "GET_ALL_TOPIC_LIST_FROM_NAMESERVER",
	310: "SEND_MESSAGE_V2",
	318: "UPDATE_NAMESRV_CONFIG",
	319: "GET_NAMESRV_CONFIG",
}

var responseCodes = map[int]string{
	CodeSuccess:      "SUCCESS",
	CodeSystemError:  "SYSTEM_ERROR",
	CodeNotSupported: "REQUEST_CODE_NOT_SUPPORTED",
}

// RequestName returns the RequestCode name, or CODE_<n>.
func RequestName(code int) string {
	if n, ok := requestCodes[code]; ok {
		return n
	}
	return "CODE_" + strconv.Itoa(code)
}

// ResponseName returns the ResponseCode name, or CODE_<n>.
func ResponseName(code int) string {
	if n, ok := responseCodes[code]; ok {
		return n
	}
	return "CODE_" + strconv.Itoa(code)
}

// Header is the JSON-serialized RemotingCommand header. Field order matches
// fastjson's alphabetical output.
type Header struct {
	Code                    int               `json:"code"`
	ExtFields               map[string]string `json:"extFields,omitempty"`
	Flag                    int               `json:"flag"`
	Language                string            `json:"language"`
	Opaque                  int32             `json:"opaque"`
	Remark                  string            `json:"remark,omitempty"`
	SerializeTypeCurrentRPC string            `json:"serializeTypeCurrentRPC"`
	Version                 int               `json:"version"`
}

// Frame is one decoded remoting command.
type Frame struct {
	SerializeType byte
	Header        Header
	Body          []byte
	Raw           []byte
}

// IsOneway reports whether the sender expects no reply.
func (f Frame) IsOneway() bool { return f.Header.Flag&FlagOneway != 0 }

// ReadFrame reads one frame from r. On error, Raw holds whatever was read.
func ReadFrame(r io.Reader) (Frame, error) {
	var f Frame
	var lenBuf [4]byte
	n, err := io.ReadFull(r, lenBuf[:])
	if err != nil {
		f.Raw = append([]byte(nil), lenBuf[:n]...)
		return f, err
	}
	total := binary.BigEndian.Uint32(lenBuf[:])
	f.Raw = append([]byte(nil), lenBuf[:]...)
	if total < 4 {
		return f, ErrBadLength
	}
	if total > MaxFrame {
		return f, ErrTooLarge
	}
	rest := make([]byte, total)
	n, err = io.ReadFull(r, rest)
	f.Raw = append(f.Raw, rest[:n]...)
	if err != nil {
		return f, err
	}
	mark := binary.BigEndian.Uint32(rest[:4])
	f.SerializeType = byte(mark >> 24)
	hdrLen := mark & 0x00ffffff
	if uint64(hdrLen) > uint64(total-4) {
		return f, ErrBadLength
	}
	hdr := rest[4 : 4+hdrLen]
	f.Body = rest[4+hdrLen:]
	switch f.SerializeType {
	case SerializeJSON:
		if err := json.Unmarshal(hdr, &f.Header); err != nil {
			return f, fmt.Errorf("%w: header: %v", ErrMalformed, err)
		}
	case SerializeRocketMQ:
		h, err := decodeBinaryHeader(hdr)
		if err != nil {
			return f, err
		}
		f.Header = h
	default:
		return f, fmt.Errorf("%w: unknown serialize type %d", ErrMalformed, f.SerializeType)
	}
	return f, nil
}

var languages = []string{"JAVA", "CPP", "DOTNET", "PYTHON", "DELPHI", "ERLANG", "RUBY", "OTHER", "HTTP", "GO", "PHP", "OMS", "RUST"}

// decodeBinaryHeader decodes the ROCKETMQ header serialization: code int16,
// language byte, version int16, opaque int32, flag int32, remark (int32 len),
// extFields (int32 len of k/v pairs, short key len, int value len).
func decodeBinaryHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < 21 {
		return h, ErrBadLength
	}
	h.Code = int(int16(binary.BigEndian.Uint16(b[0:2])))
	if int(b[2]) < len(languages) {
		h.Language = languages[b[2]]
	}
	h.Version = int(int16(binary.BigEndian.Uint16(b[3:5])))
	h.Opaque = int32(binary.BigEndian.Uint32(b[5:9]))
	h.Flag = int(int32(binary.BigEndian.Uint32(b[9:13])))
	h.SerializeTypeCurrentRPC = "ROCKETMQ"
	p := 13
	rl := int(binary.BigEndian.Uint32(b[p : p+4]))
	p += 4
	if rl < 0 || rl > len(b)-p {
		return h, ErrBadLength
	}
	h.Remark = string(b[p : p+rl])
	p += rl
	if len(b)-p < 4 {
		return h, ErrBadLength
	}
	el := int(binary.BigEndian.Uint32(b[p : p+4]))
	p += 4
	if el < 0 || el > len(b)-p {
		return h, ErrBadLength
	}
	ext := b[p : p+el]
	for len(ext) >= 2 {
		kl := int(binary.BigEndian.Uint16(ext[:2]))
		if len(ext) < 2+kl+4 {
			break
		}
		k := string(ext[2 : 2+kl])
		ext = ext[2+kl:]
		vl := int(binary.BigEndian.Uint32(ext[:4]))
		if vl < 0 || len(ext) < 4+vl {
			break
		}
		if h.ExtFields == nil {
			h.ExtFields = map[string]string{}
		}
		h.ExtFields[k] = string(ext[4 : 4+vl])
		ext = ext[4+vl:]
	}
	return h, nil
}

// Encode builds a JSON-serialized frame.
func Encode(h Header, body []byte) []byte {
	hdr, _ := json.Marshal(h)
	out := make([]byte, 8, 8+len(hdr)+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(4+len(hdr)+len(body)))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(hdr))&0x00ffffff)
	out = append(out, hdr...)
	return append(out, body...)
}

// Broker answers requests as a RocketMQ 4.9.x broker.
type Broker struct {
	// Version is MQVersion ordinal reported in replies and runtime info.
	Version     int
	VersionDesc string
	BrokerName  string
	Now         func() time.Time
	boot        time.Time
}

// NewBroker returns the default persona.
func NewBroker() *Broker {
	return &Broker{Version: 413, VersionDesc: "V4_9_4", BrokerName: "broker-a", Now: time.Now}
}

func (b *Broker) bootTime() time.Time {
	if b.boot.IsZero() {
		b.boot = b.Now().Add(-73 * time.Hour)
	}
	return b.boot
}

// Reply returns the response frame for req, its response code, and false if
// no reply should be sent (oneway or response frames).
func (b *Broker) Reply(req Frame) ([]byte, int, bool) {
	if req.IsOneway() || req.Header.Flag&FlagResponse != 0 {
		return nil, 0, false
	}
	h := Header{
		Flag:                    FlagResponse,
		Language:                "JAVA",
		Opaque:                  req.Header.Opaque,
		SerializeTypeCurrentRPC: "JSON",
		Version:                 b.Version,
	}
	var body []byte
	switch req.Header.Code {
	case CodeGetBrokerRuntime:
		h.Code = CodeSuccess
		body = b.runtimeInfo()
	case CodeGetBrokerConf:
		h.Code = CodeSuccess
		body = b.brokerConfig()
	case CodeUpdateBrokerConf, CodeHeartBeat, CodeUnregisterClient:
		h.Code = CodeSuccess
	default:
		h.Code = CodeNotSupported
		h.Remark = fmt.Sprintf(" request type %d not supported", req.Header.Code)
	}
	return Encode(h, body), h.Code, true
}

func (b *Broker) runtimeInfo() []byte {
	now := b.Now()
	boot := b.bootTime()
	table := map[string]string{
		"brokerVersionDesc":               b.VersionDesc,
		"brokerVersion":                   strconv.Itoa(b.Version),
		"bootTimestamp":                   strconv.FormatInt(boot.UnixMilli(), 10),
		"runtime":                         runtimeString(now.Sub(boot)),
		"msgPutTotalTodayNow":             "0",
		"msgGetTotalTodayNow":             "0",
		"msgPutTotalYesterdayMorning":     "0",
		"msgGetTotalYesterdayMorning":     "0",
		"msgPutTotalTodayMorning":         "0",
		"msgGetTotalTodayMorning":         "0",
		"putTps":                          "0.0 0.0 0.0",
		"getTransferedTps":                "0.0 0.0 0.0",
		"sendThreadPoolQueueSize":         "0",
		"sendThreadPoolQueueCapacity":     "10000",
		"pullThreadPoolQueueSize":         "0",
		"pullThreadPoolQueueCapacity":     "100000",
		"queryThreadPoolQueueSize":        "0",
		"queryThreadPoolQueueCapacity":    "20000",
		"commitLogDiskRatio":              "0.31",
		"commitLogMinOffset":              "0",
		"commitLogMaxOffset":              "0",
		"dispatchBehindBytes":             "0",
		"pageCacheLockTimeMills":          "0",
		"earliestMessageTimeStamp":        "-1",
		"startAcceptSendRequestTimeStamp": "0",
		"remainHowManyDataToFlush":        "0 B",
		"remainTransientStoreBufferNumbs": "2147483647",
		"putMessageEntireTimeMax":         "0",
		"putMessageAverageSize":           "0.0",
		"putMessageSizeTotal":             "0",
		"putMessageTimesTotal":            "0",
		"putMessageFailedTimes":           "0",
		"putMessageDistributeTime":        "[<=0ms]:0 [0~10ms]:0 [10~50ms]:0 [50~100ms]:0 [100~200ms]:0 [200~500ms]:0 [500ms~1s]:0 [1~2s]:0 [2~3s]:0 [3~4s]:0 [4~5s]:0 [5~10s]:0 [10s~]:0 ",
		"getMessageEntireTimeMax":         "0",
		"getFoundTps":                     "0.0 0.0 0.0",
		"getMissTps":                      "0.0 0.0 0.0",
		"getTotalTps":                     "0.0 0.0 0.0",
		"consumeQueueDiskRatio":           "0.31",
		"scheduleMessageOffset_1":         "0,0",
		"dispatchMaxBuffer":               "0",
	}
	out, _ := json.Marshal(struct {
		Table map[string]string `json:"table"`
	}{table})
	return out
}

func runtimeString(d time.Duration) string {
	s := int64(d.Seconds())
	return fmt.Sprintf("[ %d days, %d hours, %d minutes, %d seconds ]", s/86400, s%86400/3600, s%3600/60, s%60)
}

func (b *Broker) brokerConfig() []byte {
	cfg := map[string]string{
		"brokerClusterName":     "DefaultCluster",
		"brokerName":            b.BrokerName,
		"brokerId":              "0",
		"brokerRole":            "ASYNC_MASTER",
		"flushDiskType":         "ASYNC_FLUSH",
		"listenPort":            "10911",
		"namesrvAddr":           "127.0.0.1:9876",
		"rocketmqHome":          "/home/rocketmq/rocketmq-4.9.4",
		"storePathRootDir":      "/home/rocketmq/store",
		"autoCreateTopicEnable": "true",
		"deleteWhen":            "04",
		"fileReservedTime":      "48",
	}
	return []byte(FormatProperties(cfg))
}

// FormatProperties renders key=value lines in sorted order.
func FormatProperties(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(m[k])
		sb.WriteByte('\n')
	}
	return sb.String()
}

// ParseProperties parses a java.util.Properties-style body (key=value lines),
// as sent with UPDATE_BROKER_CONFIG / UPDATE_NAMESRV_CONFIG.
func ParseProperties(body []byte) map[string]string {
	var out map[string]string
	for _, line := range bytes.Split(body, []byte("\n")) {
		l := strings.TrimSpace(string(line))
		if l == "" || l[0] == '#' || l[0] == '!' {
			continue
		}
		i := strings.IndexAny(l, "=:")
		if i <= 0 {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[strings.TrimSpace(l[:i])] = strings.TrimSpace(l[i+1:])
	}
	return out
}
