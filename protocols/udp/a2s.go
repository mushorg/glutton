package udp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/a2s"
)

const maxA2SPayload = 1024

// a2sRand supplies S2C_CHALLENGE numbers; tests replace it.
var a2sRand io.Reader = rand.Reader

type parsedA2S struct {
	Direction   string `json:"direction,omitempty"`
	Command     string `json:"command,omitempty"`
	RequestType uint8  `json:"request_type,omitempty"`
	Query       string `json:"query,omitempty"`
	Challenge   string `json:"challenge,omitempty"` // hex of the wire bytes
	Status      string `json:"status,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// HandleA2S parses a Valve Source Engine query (A2S) datagram. Requests that
// a real server answers with a challenge get a 9-byte S2C_CHALLENGE so the
// client's follow-up is captured. Data responses (server info, players,
// rules) are never sent, and no reply is larger than the request, so the
// sensor cannot be used as an amplifier.
func HandleA2S(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxA2SPayload))
	copy(payload, data[:len(payload)])

	events := []parsedA2S{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("a2s", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedA2S](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "a2s"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	req, err := a2s.Parse(payload)
	frame := parsedA2S{
		Direction: "read",
		Command:   "UNKNOWN",
		Payload:   payload,
		Truncated: len(data) > maxA2SPayload,
	}
	if len(payload) >= a2s.HeaderLen {
		frame.Command = a2s.Name(req.Type)
		frame.RequestType = req.Type
		frame.Query = req.Query
		frame.Challenge = req.ChallengeHex()
	}
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse A2S query", slog.String("protocol", "a2s"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}

	logger.Info("A2S query received",
		slog.String("handler", "a2s"),
		slog.String("protocol", "a2s"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("command", frame.Command),
	)

	if !req.WantsChallenge() {
		return nil
	}
	var challenge [a2s.ChallengeLen]byte
	if _, err := io.ReadFull(a2sRand, challenge[:]); err != nil {
		logger.Error("Failed to generate A2S challenge", slog.String("protocol", "a2s"), producer.ErrAttr(err))
		return nil
	}
	resp := a2s.BuildChallenge(binary.LittleEndian.Uint32(challenge[:]))
	if len(resp) > len(data) {
		// GETCHALLENGE is 5 bytes; a 9-byte answer would amplify.
		return nil
	}
	events = append(events, parsedA2S{
		Direction:   "write",
		Command:     a2s.Name(a2s.TypeChallenge),
		RequestType: a2s.TypeChallenge,
		Challenge:   hex.EncodeToString(challenge[:]),
		Status:      a2s.Name(a2s.TypeChallenge),
		Payload:     resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send A2S challenge", slog.String("protocol", "a2s"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
