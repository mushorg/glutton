package protocols

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/rules"
)

const (
	// tlsAutoWait is how long tls: auto waits for the client to speak first.
	// Server-first protocols (POP3, SMTP, FTP) get their greeting this much
	// later when the client stays silent.
	tlsAutoWait = 500 * time.Millisecond
	// tlsSniffWait bounds the wait for the rest of the 3-byte record header
	// once the client has sent its first byte.
	tlsSniffWait = 200 * time.Millisecond
	// tlsRecordHandshake is the TLS record content type of a ClientHello.
	tlsRecordHandshake = 0x16
)

// withTLS terminates TLS before fn runs when the matched rule asks for it.
func withTLS(fn TCPHandlerFunc, log interfaces.Logger, h interfaces.Honeypot) TCPHandlerFunc {
	return func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
		if md.Rule == nil {
			return fn(ctx, conn, md)
		}
		switch md.Rule.TLS {
		case rules.TLSOn:
			return serveTLS(ctx, fn, conn, md, log, h)
		case rules.TLSAuto:
			return serveAutoTLS(ctx, fn, conn, md, log, h)
		}
		return fn(ctx, conn, md)
	}
}

// serveTLS terminates TLS for rules with tls: true and runs fn on the
// decrypted connection. If the handshake fails (a scanner that connects and
// waits, or a client that is not speaking TLS) fn never runs, so the wrapper
// produces the single event itself: payload is whatever the client sent.
func serveTLS(ctx context.Context, fn TCPHandlerFunc, conn net.Conn, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		log.Debug("Failed to set connection timeout", slog.String("protocol", "tls"), producer.ErrAttr(err))
		_ = conn.Close()
		return nil
	}
	tlsConn, info, err := helpers.TerminateTLS(conn)
	return finishTLS(ctx, fn, conn, tlsConn, info, err, md, log, h)
}

// serveAutoTLS serves rules with tls: auto. It waits briefly for the client's
// first bytes: a TLS handshake record is terminated like tls: true, anything
// else (plaintext, or silence from a client waiting for a server greeting)
// goes to fn unchanged with the peeked bytes still readable.
func serveAutoTLS(ctx context.Context, fn TCPHandlerFunc, conn net.Conn, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	bufConn := newBufferedConn(conn)
	isTLS := sniffTLS(bufConn, log)
	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		log.Debug("Failed to set connection timeout", slog.String("protocol", "tls"), producer.ErrAttr(err))
		_ = conn.Close()
		return nil
	}
	if !isTLS {
		return fn(ctx, bufConn, md)
	}
	tlsConn, info, err := helpers.TerminateTLSFrom(conn, bufConn.r)
	return finishTLS(ctx, fn, conn, tlsConn, info, err, md, log, h)
}

// sniffTLS reports whether the client opened with a TLS handshake record
// header (16 03 00..04). A silent or closed client is not TLS.
func sniffTLS(bufConn BufferedConn, log interfaces.Logger) bool {
	if err := bufConn.SetReadDeadline(time.Now().Add(tlsAutoWait)); err != nil {
		log.Debug("Failed to set TLS sniff deadline", slog.String("protocol", "tls"), producer.ErrAttr(err))
		return false
	}
	first, err := bufConn.peek(1)
	if err != nil || first[0] != tlsRecordHandshake {
		return false
	}
	if err := bufConn.SetReadDeadline(time.Now().Add(tlsSniffWait)); err != nil {
		log.Debug("Failed to set TLS sniff deadline", slog.String("protocol", "tls"), producer.ErrAttr(err))
		return false
	}
	hdr, err := bufConn.peek(3)
	if err != nil {
		// only the content type arrived in time; trust it
		var ne net.Error
		return errors.As(err, &ne) && ne.Timeout()
	}
	return looksLikeTLSRecord(hdr)
}

// looksLikeTLSRecord matches a TLS handshake record header: content type 0x16
// and a 3.x record version up to TLS 1.3's legacy 0x0304.
func looksLikeTLSRecord(b []byte) bool {
	return len(b) >= 3 && b[0] == tlsRecordHandshake && b[1] == 0x03 && b[2] <= 0x04
}

// finishTLS runs fn on a terminated TLS session, or produces the single event
// for a failed handshake itself because fn never runs.
func finishTLS(ctx context.Context, fn TCPHandlerFunc, conn, tlsConn net.Conn, info *connection.TLSInfo, err error, md connection.Metadata, log interfaces.Logger, h interfaces.Honeypot) error {
	md.TLS = info
	if err == nil {
		return fn(ctx, tlsConn, md)
	}
	log.Debug("TLS handshake failed", slog.String("protocol", "tls"), producer.ErrAttr(err))
	md.EndReason = connection.EndReasonFromRead(err)
	if perr := h.ProduceTCP(md.Rule.Target, conn, md, info.Hello, nil); perr != nil {
		log.Error("Failed to produce message", slog.String("protocol", "tls"), producer.ErrAttr(perr))
	}
	if cerr := conn.Close(); cerr != nil {
		log.Debug("Failed to close connection", slog.String("protocol", "tls"), producer.ErrAttr(cerr))
	}
	return nil
}
