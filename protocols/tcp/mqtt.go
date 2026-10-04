package tcp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/spf13/viper"
)

const (
	maxMQTTPackets     = 64
	maxMQTTDefaultBody = 64 * 1024

	mqttCONNECT     = 1
	mqttCONNACK     = 2
	mqttPUBLISH     = 3
	mqttPUBACK      = 4
	mqttPUBREC      = 5
	mqttPUBREL      = 6
	mqttPUBCOMP     = 7
	mqttSUBSCRIBE   = 8
	mqttSUBACK      = 9
	mqttUNSUBSCRIBE = 10
	mqttUNSUBACK    = 11
	mqttPINGREQ     = 12
	mqttPINGRESP    = 13
	mqttDISCONNECT  = 14
)

var mqttPacketNames = map[uint8]string{
	mqttCONNECT:     "CONNECT",
	mqttCONNACK:     "CONNACK",
	mqttPUBLISH:     "PUBLISH",
	mqttPUBACK:      "PUBACK",
	mqttPUBREC:      "PUBREC",
	mqttPUBREL:      "PUBREL",
	mqttPUBCOMP:     "PUBCOMP",
	mqttSUBSCRIBE:   "SUBSCRIBE",
	mqttSUBACK:      "SUBACK",
	mqttUNSUBSCRIBE: "UNSUBSCRIBE",
	mqttUNSUBACK:    "UNSUBACK",
	mqttPINGREQ:     "PINGREQ",
	mqttPINGRESP:    "PINGRESP",
	mqttDISCONNECT:  "DISCONNECT",
}

type parsedMQTT struct {
	Direction string   `json:"direction,omitempty"`
	Command   string   `json:"command,omitempty"`
	Packet    string   `json:"packet,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	Topic     string   `json:"topic,omitempty"`
	Topics    []string `json:"topics,omitempty"`
	QoS       uint8    `json:"qos,omitempty"`
	Payload   []byte   `json:"payload,omitempty"`
}

type mqttServer struct {
	events []parsedMQTT
	conn   net.Conn
}

func mqttPacketName(t uint8) string {
	if name, ok := mqttPacketNames[t]; ok {
		return name
	}
	return "UNKNOWN"
}

func mqttMaxBody() int {
	n := viper.GetInt("max_tcp_payload")
	if n <= 0 {
		return maxMQTTDefaultBody
	}
	if n > maxMQTTDefaultBody {
		return maxMQTTDefaultBody
	}
	return n
}

func encodeRemainingLength(n int) []byte {
	var out []byte
	for {
		digit := byte(n % 128)
		n /= 128
		if n > 0 {
			digit |= 0x80
		}
		out = append(out, digit)
		if n == 0 {
			break
		}
	}
	return out
}

func readRemainingLength(r io.Reader) (int, []byte, error) {
	var (
		value      int
		multiplier = 1
		encoded    []byte
	)
	for i := 0; i < 4; i++ {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, encoded, err
		}
		encoded = append(encoded, b[0])
		value += int(b[0]&0x7f) * multiplier
		if b[0]&0x80 == 0 {
			return value, encoded, nil
		}
		multiplier *= 128
	}
	return 0, encoded, errors.New("invalid MQTT remaining length")
}

func mqttString(buf []byte) (string, []byte, bool) {
	if len(buf) < 2 {
		return "", buf, false
	}
	n := int(binary.BigEndian.Uint16(buf[:2]))
	buf = buf[2:]
	if n > len(buf) {
		return "", buf, false
	}
	return string(buf[:n]), buf[n:], true
}

func mqttUint16(buf []byte) (uint16, []byte, bool) {
	if len(buf) < 2 {
		return 0, buf, false
	}
	return binary.BigEndian.Uint16(buf[:2]), buf[2:], true
}

func encodeMQTT(packetType uint8, flags uint8, body []byte) []byte {
	first := (packetType << 4) | (flags & 0x0f)
	out := append([]byte{first}, encodeRemainingLength(len(body))...)
	return append(out, body...)
}

func decodeMQTT(first byte, body []byte) parsedMQTT {
	packetType := first >> 4
	flags := first & 0x0f
	frame := parsedMQTT{
		Packet:  mqttPacketName(packetType),
		Command: mqttPacketName(packetType),
	}
	switch packetType {
	case mqttCONNECT:
		_, rest, ok := mqttString(body)
		if !ok || len(rest) < 4 {
			return frame
		}
		rest = rest[1:] // protocol level
		connectFlags := rest[0]
		rest = rest[3:] // flags + keep alive
		clientID, rest, ok := mqttString(rest)
		if !ok {
			return frame
		}
		frame.ClientID = clientID
		if connectFlags&0x04 != 0 {
			_, rest, ok = mqttString(rest) // will topic
			if !ok {
				return frame
			}
			_, rest, ok = mqttString(rest) // will message
			if !ok {
				return frame
			}
		}
		if connectFlags&0x80 != 0 {
			user, rest2, ok := mqttString(rest)
			if !ok {
				return frame
			}
			frame.Username = user
			rest = rest2
		}
		if connectFlags&0x40 != 0 {
			_, _, _ = mqttString(rest) // password, not stored
		}
	case mqttPUBLISH:
		frame.QoS = (flags >> 1) & 0x03
		topic, rest, ok := mqttString(body)
		if !ok {
			return frame
		}
		frame.Topic = topic
		if frame.QoS > 0 {
			_, rest, ok = mqttUint16(rest)
			if !ok {
				return frame
			}
		}
		_ = rest
	case mqttSUBSCRIBE, mqttUNSUBSCRIBE:
		id, rest, ok := mqttUint16(body)
		if !ok {
			return frame
		}
		_ = id
		var topics []string
		for len(rest) > 0 {
			topic, next, ok := mqttString(rest)
			if !ok {
				break
			}
			topics = append(topics, topic)
			rest = next
			if packetType == mqttSUBSCRIBE {
				if len(rest) < 1 {
					break
				}
				if frame.QoS == 0 {
					frame.QoS = rest[0] & 0x03
				}
				rest = rest[1:]
			}
		}
		frame.Topics = topics
		if len(topics) == 1 {
			frame.Topic = topics[0]
		}
	case mqttPUBACK, mqttPUBREC, mqttPUBREL, mqttPUBCOMP, mqttUNSUBACK:
		if id, _, ok := mqttUint16(body); ok {
			_ = id
		}
	}
	return frame
}

func mqttPublishID(body []byte) (uint16, bool) {
	_, rest, ok := mqttString(body)
	if !ok {
		return 0, false
	}
	id, _, ok := mqttUint16(rest)
	return id, ok
}

func mqttPacketID(body []byte) (uint16, bool) {
	id, _, ok := mqttUint16(body)
	return id, ok
}

func mqttSubscribeQoS(body []byte) []byte {
	_, rest, ok := mqttUint16(body)
	if !ok {
		return nil
	}
	var qos []byte
	for len(rest) > 0 {
		_, next, ok := mqttString(rest)
		if !ok || len(next) < 1 {
			break
		}
		qos = append(qos, next[0]&0x03)
		rest = next[1:]
	}
	return qos
}

func (s *mqttServer) read() (byte, []byte, []byte, error) {
	var first [1]byte
	if _, err := io.ReadFull(s.conn, first[:]); err != nil {
		return 0, nil, nil, err
	}
	remaining, lenBytes, err := readRemainingLength(s.conn)
	if err != nil {
		return 0, nil, nil, err
	}
	maxBody := mqttMaxBody()
	if remaining < 0 || remaining > maxBody {
		return 0, nil, nil, errors.New("MQTT remaining length exceeds cap")
	}
	body := make([]byte, remaining)
	if remaining > 0 {
		if _, err := io.ReadFull(s.conn, body); err != nil {
			return 0, nil, nil, err
		}
	}
	raw := make([]byte, 0, 1+len(lenBytes)+len(body))
	raw = append(raw, first[0])
	raw = append(raw, lenBytes...)
	raw = append(raw, body...)
	return first[0], body, raw, nil
}

func (s *mqttServer) write(raw []byte, frame parsedMQTT) error {
	if _, err := s.conn.Write(raw); err != nil {
		return err
	}
	frame.Direction = "write"
	frame.Payload = raw
	s.events = append(s.events, frame)
	return nil
}

func (s *mqttServer) recordRead(first byte, body, raw []byte) parsedMQTT {
	frame := decodeMQTT(first, body)
	frame.Direction = "read"
	frame.Payload = raw
	s.events = append(s.events, frame)
	return frame
}

func mqttReply(first byte, body []byte) (raw []byte, frame parsedMQTT, ok bool) {
	packetType := first >> 4
	flags := first & 0x0f
	switch packetType {
	case mqttCONNECT:
		raw = encodeMQTT(mqttCONNACK, 0, []byte{0x00, 0x00})
		return raw, parsedMQTT{Packet: "CONNACK", Command: "CONNACK"}, true
	case mqttPINGREQ:
		raw = encodeMQTT(mqttPINGRESP, 0, nil)
		return raw, parsedMQTT{Packet: "PINGRESP", Command: "PINGRESP"}, true
	case mqttSUBSCRIBE:
		id, okID := mqttPacketID(body)
		if !okID {
			return nil, parsedMQTT{}, false
		}
		qos := mqttSubscribeQoS(body)
		ackBody := make([]byte, 2+len(qos))
		binary.BigEndian.PutUint16(ackBody[:2], id)
		copy(ackBody[2:], qos)
		raw = encodeMQTT(mqttSUBACK, 0, ackBody)
		return raw, parsedMQTT{Packet: "SUBACK", Command: "SUBACK"}, true
	case mqttUNSUBSCRIBE:
		id, okID := mqttPacketID(body)
		if !okID {
			return nil, parsedMQTT{}, false
		}
		ackBody := make([]byte, 2)
		binary.BigEndian.PutUint16(ackBody, id)
		raw = encodeMQTT(mqttUNSUBACK, 0, ackBody)
		return raw, parsedMQTT{Packet: "UNSUBACK", Command: "UNSUBACK"}, true
	case mqttPUBLISH:
		qos := (flags >> 1) & 0x03
		if qos == 0 {
			return nil, parsedMQTT{}, false
		}
		id, okID := mqttPublishID(body)
		if !okID {
			return nil, parsedMQTT{}, false
		}
		idBody := make([]byte, 2)
		binary.BigEndian.PutUint16(idBody, id)
		if qos == 1 {
			raw = encodeMQTT(mqttPUBACK, 0, idBody)
			return raw, parsedMQTT{Packet: "PUBACK", Command: "PUBACK"}, true
		}
		raw = encodeMQTT(mqttPUBREC, 0, idBody)
		return raw, parsedMQTT{Packet: "PUBREC", Command: "PUBREC"}, true
	case mqttPUBREL:
		id, okID := mqttPacketID(body)
		if !okID {
			return nil, parsedMQTT{}, false
		}
		idBody := make([]byte, 2)
		binary.BigEndian.PutUint16(idBody, id)
		raw = encodeMQTT(mqttPUBCOMP, 0, idBody)
		return raw, parsedMQTT{Packet: "PUBCOMP", Command: "PUBCOMP"}, true
	default:
		return nil, parsedMQTT{}, false
	}
}

// HandleMQTT takes a net.Conn and does MQTT 3.1.1 communication
func HandleMQTT(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	server := &mqttServer{events: []parsedMQTT{}, conn: conn}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceTCP("mqtt", conn, md, helpers.FirstOrEmpty[parsedMQTT](server.events).Payload, server.events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "mqtt"), producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Debug("Failed to close MQTT connection", slog.String("protocol", "mqtt"), producer.ErrAttr(err))
		}
	}()

	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	loggedConnect := false

	i := 0
	for ; i < maxMQTTPackets; i++ {
		if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
			logger.Debug("Failed to set connection timeout", slog.String("protocol", "mqtt"), producer.ErrAttr(err))
			endReason = connection.EndTimeout
			return nil
		}
		first, body, raw, err := server.read()
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				logger.Debug("Failed to read data", slog.String("protocol", "mqtt"), producer.ErrAttr(err))
			}
			endReason = connection.EndReasonFromRead(err)
			break
		}
		frame := server.recordRead(first, body, raw)
		if frame.Packet == "CONNECT" && !loggedConnect {
			loggedConnect = true
			logger.Info("MQTT CONNECT",
				slog.String("handler", "mqtt"),
				slog.String("src_ip", host),
				slog.String("src_port", port),
				slog.Int("dest_port", int(md.TargetPort)),
				slog.String("client_id", frame.ClientID),
			)
		}
		reply, writeFrame, ok := mqttReply(first, body)
		if !ok {
			if frame.Packet == "DISCONNECT" {
				return nil
			}
			continue
		}
		if err := server.write(reply, writeFrame); err != nil {
			logger.Error("Failed to write message", slog.String("protocol", "mqtt"), producer.ErrAttr(err))
			endReason = connection.EndWriteError
			return err
		}
	}
	if i >= maxMQTTPackets {
		endReason = connection.EndMaxFrames
	}
	return nil
}
