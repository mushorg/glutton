package udp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/dtls"
)

const maxDTLSPayload = 1024

// dtlsSecret keys the stateless HelloVerifyRequest cookie. It is random per
// process; tests replace it.
var dtlsSecret = func() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails since Go 1.24
	return b
}()

type parsedDTLS struct {
	Direction     string   `json:"direction,omitempty"`
	Command       string   `json:"command,omitempty"`
	ClientVersion string   `json:"client_version,omitempty"`
	SessionID     string   `json:"session_id,omitempty"`
	CookiePresent bool     `json:"cookie_present,omitempty"` // read: the hello carried a non-empty cookie
	CookieValid   bool     `json:"cookie_valid,omitempty"`   // read: the cookie is the one we would issue this source
	CipherSuites  []uint16 `json:"cipher_suites,omitempty"`
	Extensions    []uint16 `json:"extensions,omitempty"` // extension types in wire order
	ServerName    string   `json:"server_name,omitempty"`
	Status        string   `json:"status,omitempty"`
	Payload       []byte   `json:"payload,omitempty"`
	Truncated     bool     `json:"truncated,omitempty"`
}

// HandleDTLS parses a DTLS ClientHello and answers it with a HelloVerifyRequest
// carrying a stateless cookie bound to the source address, so scanners send
// their second, cookie-bearing hello (captured as its own event). A hello
// whose cookie is already valid for the source is recorded but not answered:
// the handshake itself is not emulated. The reply is smaller than any
// ClientHello, so the handler is no amplifier.
func HandleDTLS(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxDTLSPayload))
	copy(payload, data[:len(payload)])

	events := []parsedDTLS{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("dtls", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedDTLS](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "dtls"), producer.ErrAttr(err))
		}
	}()

	frame := parsedDTLS{
		Direction: "read",
		Command:   "UNKNOWN",
		Payload:   payload,
		Truncated: len(data) > maxDTLSPayload,
	}
	hello, err := dtls.ParseClientHello(payload)
	cookie := dtls.Cookie(dtlsSecret, srcAddr.IP, srcAddr.Port)
	if hello != nil {
		frame.ClientVersion = dtls.VersionString(hello.ClientVersion)
		frame.SessionID = hex.EncodeToString(hello.SessionID)
		frame.CookiePresent = len(hello.Cookie) > 0
		frame.CookieValid = frame.CookiePresent && bytes.Equal(hello.Cookie, cookie)
		frame.CipherSuites = hello.CipherSuites
		frame.ServerName = hello.ServerName
		for _, e := range hello.Extensions {
			frame.Extensions = append(frame.Extensions, e.Type)
		}
	}
	if err != nil {
		events = append(events, frame)
		logger.Debug("Failed to parse DTLS ClientHello", slog.String("protocol", "dtls"), producer.ErrAttr(err), slog.Int("bytes", len(payload)))
		return nil
	}
	frame.Command = "ClientHello"
	events = append(events, frame)

	logger.Info("DTLS ClientHello received",
		slog.String("handler", "dtls"),
		slog.String("protocol", "dtls"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("client_version", frame.ClientVersion),
		slog.Bool("cookie_present", frame.CookiePresent),
	)

	if frame.CookieValid {
		return nil
	}
	resp := dtls.BuildHelloVerifyRequest(hello.Sequence, cookie)
	events = append(events, parsedDTLS{
		Direction: "write",
		Command:   "HelloVerifyRequest",
		Status:    "ok",
		Payload:   resp,
	})
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send DTLS reply", slog.String("protocol", "dtls"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
