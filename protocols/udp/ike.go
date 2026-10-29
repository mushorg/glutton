package udp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/ike"
)

const maxIKEPayload = 4096

// ikeRand supplies responder SPIs, KE values and nonces; tests replace it.
var ikeRand io.Reader = rand.Reader

type parsedIKE struct {
	Direction  string   `json:"direction,omitempty"`
	Command    string   `json:"command,omitempty"` // exchange name
	Status     string   `json:"status,omitempty"`  // notify name or IKE_SA_INIT on writes
	Version    string   `json:"version,omitempty"`
	SPIi       string   `json:"spi_i,omitempty"`
	SPIr       string   `json:"spi_r,omitempty"`
	Encryption []string `json:"encryption,omitempty"`
	PRF        []string `json:"prf,omitempty"`
	Integrity  []string `json:"integrity,omitempty"`
	DHGroups   []string `json:"dh_groups,omitempty"`
	Hash       []string `json:"hash,omitempty"`        // IKEv1 hash algorithms
	AuthMethod []string `json:"auth_method,omitempty"` // IKEv1 authentication methods
	Life       []string `json:"life,omitempty"`        // IKEv1 lifetime, seconds
	KEGroup    string   `json:"ke_group,omitempty"`
	Identity   string   `json:"identity,omitempty"` // IKEv1 ID payload
	IDType     string   `json:"id_type,omitempty"`
	NonceLen   int      `json:"nonce_len,omitempty"` // IKEv1 nonce length
	Notifies   []string `json:"notifies,omitempty"`
	VendorIDs  []string `json:"vendor_ids,omitempty"` // hex
	NATT       bool     `json:"nat_t,omitempty"`      // non-ESP marker present (udp/4500)
	Prefix     string   `json:"prefix,omitempty"`     // hex of non-IKE bytes before the header
	Payload    []byte   `json:"payload,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
}

func ikeFrame(direction string, m ike.Message) parsedIKE {
	f := parsedIKE{
		Direction:  direction,
		Command:    ike.ExchangeName(m.Exchange),
		Version:    m.VersionString(),
		SPIi:       hex.EncodeToString(m.SPIi[:]),
		SPIr:       hex.EncodeToString(m.SPIr[:]),
		Encryption: m.Offered(ike.TransformENCR),
		PRF:        m.Offered(ike.TransformPRF),
		Integrity:  m.Offered(ike.TransformINTEG),
		DHGroups:   m.Offered(ike.TransformDH),
		Notifies:   m.NotifyNames(),
		VendorIDs:  m.VendorIDHex(),
		Identity:   m.Identity,
		IDType:     m.IDType,
		NonceLen:   m.NonceLen,
	}
	if len(m.V1Proposals) > 0 {
		f.Encryption = m.V1Offered("encryption")
		f.Hash = m.V1Offered("hash")
		f.AuthMethod = m.V1Offered("auth")
		f.DHGroups = m.V1Offered("group")
		f.Life = m.V1Offered("life")
	}
	if m.HasKE {
		f.KEGroup = ike.Transform{Type: ike.TransformDH, ID: m.KEGroup}.Name()
	}
	return f
}

// HandleIKE parses an IKE (ISAKMP) datagram on udp/500 or udp/4500 and
// answers IKEv2 IKE_SA_INIT and IKEv1 Main Mode like a gateway that accepts
// legacy proposals but requires a 2048-bit or EC Diffie-Hellman group for
// IKEv2. IKEv1 Aggressive Mode is recorded (identity, KE, nonce length) and
// not answered. Messages behind a non-standard prefix are recorded without
// a reply. A reply larger than twice the request is dropped.
func HandleIKE(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxIKEPayload))
	copy(payload, data[:len(payload)])
	truncated := len(data) > maxIKEPayload

	events := []parsedIKE{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("ike", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedIKE](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "ike"), producer.ErrAttr(err))
		}
	}()

	if len(payload) == 0 {
		return nil
	}

	msgBytes, natt := ike.StripNonESPMarker(payload)
	var prefix []byte
	if !natt && !ike.LooksLikeIKE(payload) {
		if off, ok := ike.FindPrefixedHeader(payload); ok {
			prefix, msgBytes = payload[:off], payload[off:]
		}
	}
	msg, err := ike.Parse(msgBytes)
	frame := parsedIKE{Direction: "read"}
	switch {
	case msg.HeaderValid():
		frame = ikeFrame("read", msg)
	case len(msgBytes) >= ike.HeaderLen:
		frame.Command = "malformed"
	}
	frame.NATT = natt
	if prefix != nil {
		frame.Prefix = hex.EncodeToString(prefix)
	}
	frame.Payload = payload
	frame.Truncated = truncated
	events = append(events, frame)
	if err != nil {
		logger.Debug("Failed to parse IKE message", slog.String("protocol", "ike"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}

	logger.Info("IKE packet received",
		slog.String("handler", "ike"),
		slog.String("protocol", "ike"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("version", frame.Version),
		slog.String("exchange", frame.Command),
		slog.Int("prefix_len", len(prefix)),
	)
	if prefix != nil {
		// a gateway reads a datagram without the non-ESP marker as ESP and drops it
		return nil
	}

	reply, ok, err := ike.BuildReply(msg, ikeRand)
	if err != nil {
		logger.Error("Failed to build IKE reply", slog.String("protocol", "ike"), producer.ErrAttr(err))
		return nil
	}
	if !ok {
		reply, ok, err = ike.BuildReplyV1(msg, ikeRand)
		if err != nil {
			logger.Error("Failed to build IKE reply", slog.String("protocol", "ike"), producer.ErrAttr(err))
			return nil
		}
		if !ok {
			return nil
		}
	}

	resp := reply.Data
	if natt {
		resp = append([]byte{0, 0, 0, 0}, resp...)
	}
	// a one-transform Main Mode message 1 must not turn into amplification
	if len(resp) > 2*len(data) {
		logger.Debug("Skipped IKE reply larger than twice the request", slog.String("protocol", "ike"), slog.Int("request", len(data)), slog.Int("reply", len(resp)))
		return nil
	}
	write := parsedIKE{
		Direction: "write",
		Command:   ike.ExchangeName(ike.ExchangeSAInit),
		Status:    reply.Status,
		Version:   "2.0",
		SPIi:      frame.SPIi,
		SPIr:      hex.EncodeToString(reply.SPIr[:]),
		NATT:      natt,
		Payload:   resp,
	}
	if reply.V1 != nil || msg.Version>>4 == 1 {
		write.Command = ike.ExchangeName(2) // IDENTITY_PROTECTION
		write.Version = "1.0"
	}
	if c := reply.Choice; c != nil {
		write.Encryption = []string{c.ENCR.Name()}
		write.PRF = []string{c.PRF.Name()}
		if c.INTEG != nil {
			write.Integrity = []string{c.INTEG.Name()}
		}
		write.DHGroups = []string{c.DH.Name()}
		if reply.Status == ike.ExchangeName(ike.ExchangeSAInit) {
			write.KEGroup = c.DH.Name()
		}
	}
	if c := reply.V1; c != nil {
		t := c.Transform
		write.Encryption = []string{t.EncryptionName()}
		write.Hash = []string{t.HashName()}
		write.AuthMethod = []string{t.AuthName()}
		write.DHGroups = []string{t.GroupName()}
		if life := t.LifeString(); life != "" {
			write.Life = []string{life}
		}
	}
	events = append(events, write)
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send IKE reply", slog.String("protocol", "ike"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
