package udp

import (
	"context"
	"encoding/hex"
	"log/slog"
	"math/rand/v2"
	"net"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/snmp"
)

// maxSNMPPayload caps the stored datagram.
const maxSNMPPayload = 1024

// snmpAgent is the read-only device persona; tests swap it for a
// deterministic one.
var snmpAgent = snmp.NewAgent(rand.Uint64(), time.Now)

type parsedSNMP struct {
	Direction      string   `json:"direction,omitempty"`
	Command        string   `json:"command,omitempty"`
	Version        string   `json:"version,omitempty"`
	Community      string   `json:"community,omitempty"`
	RequestID      int64    `json:"request_id,omitempty"`
	NonRepeaters   int64    `json:"non_repeaters,omitempty"`
	MaxRepetitions int64    `json:"max_repetitions,omitempty"`
	OIDs           []string `json:"oids,omitempty"`
	// SNMPv3: msgID, msgFlags, the USM user and engineID (hex) the client
	// sent, and the scoped PDU's context name.
	MsgID        int64  `json:"msg_id,omitempty"`
	MsgFlags     int    `json:"msg_flags,omitempty"`
	SecurityName string `json:"security_name,omitempty"`
	EngineID     string `json:"engine_id,omitempty"`
	ContextName  string `json:"context_name,omitempty"`
	Status       string `json:"status,omitempty"`
	Payload      []byte `json:"payload,omitempty"`
	Truncated    bool   `json:"truncated,omitempty"`
}

// HandleSNMP parses an SNMP datagram and answers like a read-only embedded
// device (community "public", system group only). v1/v2c replies are never
// larger than the request: a response that does not fit becomes a tooBig
// error. SNMPv3 USM discovery gets a Report (see snmp.Agent). Other
// communities, other v3 messages and non-request PDUs are recorded without a
// reply, as a real agent drops them.
func HandleSNMP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxSNMPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedSNMP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("snmp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedSNMP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "snmp"), producer.ErrAttr(err))
		}
	}()

	frame := parsedSNMP{Direction: "read", Command: "unknown", Payload: payload, Truncated: len(data) > maxSNMPPayload}
	msg, err := snmp.Parse(data)
	if err != nil {
		events = append(events, frame)
		logger.Debug("Failed to parse SNMP datagram", slog.String("protocol", "snmp"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	frame.Version = snmp.VersionName(msg.Version)
	frame.Community = msg.Community
	if msg.PDUType != 0 {
		frame.Command = snmp.PDUName(msg.PDUType)
		frame.RequestID = msg.RequestID
		if msg.PDUType == snmp.PDUGetBulk {
			frame.NonRepeaters = msg.NonRepeaters
			frame.MaxRepetitions = msg.MaxRepetitions
		}
		for _, o := range msg.OIDs {
			frame.OIDs = append(frame.OIDs, o.String())
		}
	}
	if msg.Version == snmp.Version3 {
		frame.MsgID = msg.MsgID
		frame.MsgFlags = int(msg.Flags)
		frame.SecurityName = msg.UserName
		frame.EngineID = hex.EncodeToString(msg.EngineID)
		frame.ContextName = msg.ContextName
	}
	events = append(events, frame)

	logger.Info("SNMP request received",
		slog.String("handler", "snmp"),
		slog.String("protocol", "snmp"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
		slog.String("community", frame.Community),
	)

	resp, status := snmpAgent.Respond(msg, len(data))
	if resp == nil {
		return nil
	}
	respType := byte(snmp.PDUResponse)
	if msg.Version == snmp.Version3 {
		respType = snmp.PDUReport
	}
	events = append(events, parsedSNMP{Direction: "write", Command: snmp.PDUName(respType), Status: status, Payload: resp})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send SNMP reply", slog.String("protocol", "snmp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
