package banners

import "encoding/binary"

// ActiveMQ's OpenWire transport (tcp/61616) is server-first: the broker sends
// its WireFormatInfo on connect, before the client's own. The persona is
// ActiveMQ Classic 5.18.2 on Oracle JDK 11 under Ubuntu 22.04, the last 5.18
// release before the CVE-2023-46604 fix (5.18.3), so exploit scanners that key
// on ProviderVersion send their ExceptionResponse class-load frame. nmap
// match: apachemq p/ActiveMQ OpenWire transport/ v/$4/ i/Java $1; arch: $3/
// o/Linux $2/.

// openwireVersion is OpenWire protocol version 12, the default since 5.14.
const openwireVersion = 12

// OpenWire primitive map value types (MarshallingSupport).
const (
	owBoolean = 1
	owInteger = 5
	owLong    = 6
	owString  = 9
)

// openwireProperty is one WireFormatInfo property; value is bool, int32,
// int64 or string.
type openwireProperty struct {
	key   string
	value any
}

// openwireProperties are the broker defaults in the order ActiveMQ's
// HashMap marshals them.
var openwireProperties = []openwireProperty{
	{"TcpNoDelayEnabled", true},
	{"SizePrefixDisabled", false},
	{"CacheSize", int32(1024)},
	{"ProviderName", "ActiveMQ"},
	{"StackTraceEnabled", true},
	{"PlatformDetails", "JVM: 11.0.21, 11.0.21+9-LTS-193, Oracle Corporation, OS: Linux, 5.15.0-91-generic, amd64"},
	{"CacheEnabled", true},
	{"TightEncodingEnabled", true},
	{"MaxFrameSize", int64(104857600)},
	{"MaxInactivityDuration", int64(30000)},
	{"MaxInactivityDurationInitalDelay", int64(10000)},
	{"ProviderVersion", "5.18.2"},
}

func appendOpenwireUTF(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	return append(b, s...)
}

// openwireWireFormatInfo is the loose-encoded WireFormatInfo command: size
// prefix, type 1, the "ActiveMQ" magic, the version, then the marshalled
// property map as a byte sequence (present flag, length, entry count, and per
// entry a UTF key, a type byte and the value).
var openwireWireFormatInfo = func() []byte {
	props := binary.BigEndian.AppendUint32(nil, uint32(len(openwireProperties)))
	for _, p := range openwireProperties {
		props = appendOpenwireUTF(props, p.key)
		switch v := p.value.(type) {
		case bool:
			props = append(props, owBoolean)
			if v {
				props = append(props, 1)
			} else {
				props = append(props, 0)
			}
		case int32:
			props = binary.BigEndian.AppendUint32(append(props, owInteger), uint32(v))
		case int64:
			props = binary.BigEndian.AppendUint64(append(props, owLong), uint64(v))
		case string:
			props = appendOpenwireUTF(append(props, owString), v)
		default:
			panic("openwire: unsupported property type")
		}
	}
	body := []byte{1}
	body = append(body, "ActiveMQ"...)
	body = binary.BigEndian.AppendUint32(body, openwireVersion)
	body = append(body, 1)
	body = binary.BigEndian.AppendUint32(body, uint32(len(props)))
	body = append(body, props...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}()

// OpenWireFollowUp answers the client's first message after the
// WireFormatInfo. The broker sends nothing back to a client's WireFormatInfo
// or to a frame it cannot unmarshal; it drops the transport on the
// unmarshalling error a probe or the CVE-2023-46604 ExceptionResponse causes,
// so the honeypot hangs up silently instead of answering with random bytes.
func OpenWireFollowUp([]byte) (Response, bool) {
	return Response{Name: "openwire", NoReply: true, Close: true}, true
}
