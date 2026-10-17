package udp

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/recall"
	"github.com/mushorg/glutton/protocols/tcp/enip"
	sipproto "github.com/mushorg/glutton/protocols/tcp/sip"
	"github.com/mushorg/glutton/protocols/udp/a2s"
	"github.com/mushorg/glutton/protocols/udp/ddp"
	"github.com/mushorg/glutton/protocols/udp/dtls"
	"github.com/mushorg/glutton/protocols/udp/ike"
	"github.com/mushorg/glutton/protocols/udp/knx"
	"github.com/mushorg/glutton/protocols/udp/rip"
	"github.com/mushorg/glutton/protocols/udp/rtps"
	"github.com/mushorg/glutton/protocols/udp/steam"
	"github.com/mushorg/glutton/protocols/udp/tftp"
	"github.com/mushorg/glutton/protocols/udp/wsd"
)

const maxUDPPayload = 1024

type parsedUDP struct {
	Direction   string `json:"direction,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// udpMatcher detects one protocol the catch-all hands to a dedicated handler.
type udpMatcher struct {
	name   string
	match  func(srcAddr *net.UDPAddr, data []byte) bool
	handle func(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error
}

func payloadMatch(fn func([]byte) bool) func(*net.UDPAddr, []byte) bool {
	return func(_ *net.UDPAddr, data []byte) bool { return fn(data) }
}

// udpMatchers are all evaluated on each datagram; when several match,
// pickDispatch chooses the handler.
var udpMatchers = []udpMatcher{
	{"sip", payloadMatch(sipproto.LooksLikeSIP), HandleSIP},
	{"raknet", payloadMatch(looksLikeRakNet), HandleRakNet},
	{"kerberos", payloadMatch(looksLikeKerberos), HandleKerberos},
	{"coap", payloadMatch(looksLikeCoAP), HandleCoAP},
	{"ike", payloadMatch(ike.LooksLikeIKE), HandleIKE},
	{"a2s", payloadMatch(a2s.LooksLikeA2S), HandleA2S},
	{"steam", payloadMatch(steam.LooksLikeSteam), HandleSteam},
	{"ddp", payloadMatch(ddp.LooksLikeDDP), HandleDDP},
	{"knx", payloadMatch(knx.LooksLikeKNX), HandleKNX},
	{"dtls", payloadMatch(dtls.LooksLikeDTLS), HandleDTLS},
	{"rtps", payloadMatch(rtps.LooksLikeRTPS), HandleRTPS},
	{"wsdiscovery", payloadMatch(wsd.LooksLikeWSD), HandleWSDiscovery},
	{"hiflying", looksLikeHiFlying, HandleHiFlying},
	{"rip", payloadMatch(rip.LooksLikeRIP), HandleRIP},
	{"tftp", payloadMatch(tftp.LooksLikeTFTP), HandleTFTP},
	{"enip", payloadMatch(enip.LooksLikeListRequest), HandleENIP},
}

// pickDispatch chooses among n matching protocols; it is replaced in tests
// for a deterministic choice.
var pickDispatch = func(n int) int { return rand.IntN(n) }

// dispatchRecall remembers which protocol was picked per source IP and
// destination port, so a returning source meets the same handler; tests swap
// it.
var dispatchRecall = recall.Shared

func HandleUDP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	// RTP from a caller to the media port of a call the sip handler answered
	if handleSIPMedia(srcAddr, dstAddr, data) {
		return nil
	}
	var candidates []udpMatcher
	for _, m := range udpMatchers {
		if m.match(srcAddr, data) {
			candidates = append(candidates, m)
		}
	}
	if len(candidates) > 0 {
		m := candidates[0]
		if len(candidates) > 1 {
			names := make([]string, len(candidates))
			for i, c := range candidates {
				names[i] = c.name
			}
			m = candidates[dispatchRecall.Choose(fmt.Sprintf("dispatch/udp/%d", dstAddr.Port), srcAddr.IP, names, pickDispatch)]
			log.Debug("several protocols match the datagram",
				slog.String("protocol", "udp"), slog.Any("candidates", names), slog.String("picked", m.name))
		}
		return m.handle(ctx, srcAddr, dstAddr, data, md, log, h)
	}

	truncated := len(data) > maxUDPPayload
	payload := make([]byte, min(len(data), maxUDPPayload))
	copy(payload, data[:len(payload)])

	hash := ""
	if len(payload) > 0 {
		hash = helpers.SHA256Hex(payload)
	}
	events := []parsedUDP{{
		Direction:   "read",
		Payload:     payload,
		PayloadHash: hash,
		Truncated:   truncated,
	}}
	defer func() {
		md.EndReason = connection.EndHandlerClose
		if err := h.ProduceUDP("udp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedUDP](events).Payload, events); err != nil {
			log.Error("Failed to produce message", slog.String("protocol", "udp"), producer.ErrAttr(err))
		}
	}()

	if _, err := helpers.Store(payload, "payloads"); err != nil {
		log.Error("failed to store UDP payload", slog.String("protocol", "udp"), producer.ErrAttr(err))
	}
	return nil
}
