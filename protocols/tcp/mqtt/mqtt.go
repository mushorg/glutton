// Package mqtt recognizes the start of an MQTT session. It performs no I/O.
package mqtt

// PeekLen is enough bytes to see the fixed header, the protocol name and the
// protocol level of a CONNECT (1 + up to 4 length bytes + 2 + 6 + 1).
const PeekLen = 14

const (
	packetConnect = 0x10 // CONNECT with its reserved flag bits clear
	maxRemaining  = 268435455
)

// LooksLikeConnect reports whether b starts with an MQTT CONNECT: the fixed
// header, a remaining length that covers the variable header, the protocol
// name "MQTT" (levels 3, 4, 5) or "MQIsdp" (level 3) and its level byte.
// Bytes after the level are ignored.
func LooksLikeConnect(b []byte) bool {
	if len(b) < 2 || b[0] != packetConnect {
		return false
	}
	remaining, i := 0, 1
	for shift := 0; ; shift += 7 {
		if i >= len(b) || shift > 21 {
			return false
		}
		c := b[i]
		i++
		remaining |= int(c&0x7f) << shift
		if c&0x80 == 0 {
			break
		}
	}
	if remaining > maxRemaining || len(b) < i+2 {
		return false
	}
	nameLen := int(b[i])<<8 | int(b[i+1])
	i += 2
	var minLevel, maxLevel byte
	switch {
	case nameLen == 4 && len(b) >= i+4 && string(b[i:i+4]) == "MQTT":
		minLevel, maxLevel = 3, 5
	case nameLen == 6 && len(b) >= i+6 && string(b[i:i+6]) == "MQIsdp":
		minLevel, maxLevel = 3, 3
	default:
		return false
	}
	i += nameLen
	if len(b) <= i || b[i] < minLevel || b[i] > maxLevel {
		return false
	}
	// name length field + name + level + connect flags + keep alive
	return remaining >= 2+nameLen+1+1+2
}
