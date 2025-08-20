package tcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/spf13/viper"
)

type parsedPassThrough struct {
	Direction   string `json:"direction,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"` // Used for easier identification, can remove
}

type passThroughServer struct {
	events []parsedPassThrough
	conn   net.Conn
	target string
	source string
}

type loggingWriter struct {
	dst     net.Conn
	server  *passThroughServer
	logger  interfaces.Logger
	capture bool
	dir     string
}

func (lw *loggingWriter) Write(p []byte) (int, error) {
	lw.server.logPayload(lw.dir, p, lw.logger)
	lw.server.recordEvent(lw.dir, p, lw.capture)
	return lw.dst.Write(p)
}

// checks whether the payload can be converted to text, to prevent expensive hex coding.
func (srv *passThroughServer) isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	printable := 0
	for _, b := range data {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}

	return (printable*100)/len(data) > 80 // threshold value --> 80%
}

// logs the payload hex or payload text.
func (srv *passThroughServer) logPayload(direction string, data []byte, logger interfaces.Logger) {
	if len(data) == 0 {
		return
	}

	fields := []any{
		slog.String("direction", direction),
		slog.Int("length", len(data)),
		slog.String("sha256", fmt.Sprintf("%x", sha256.Sum256(data))),
	}

	if srv.isLikelyText(data) {
		fields = append(fields, slog.String("payload", string(data)))
	} else {
		fields = append(fields, slog.String("hex", hex.EncodeToString(data)))
	}

	logger.Info("payload_transferred", fields...)
}

// records the events in the server
func (srv *passThroughServer) recordEvent(dir string, buf []byte, capture bool) {
	if !capture {
		return
	}
	hash := sha256.Sum256(buf)

	payload := append([]byte(nil), buf...) // defensive copy

	srv.events = append(srv.events, parsedPassThrough{
		Direction:   dir,
		Payload:     payload,
		PayloadHash: fmt.Sprintf("%x", hash[:]),
	})
}

// pipeBidirectional handles data transfer between the two connections
func pipeBidirectional(src, dst net.Conn, server *passThroughServer, logger interfaces.Logger, capture bool, errChan chan error) {
	direction := getDirection(src, dst)
	writer := &loggingWriter{dst: dst, server: server, logger: logger, capture: capture, dir: direction}

	// source to target
	go func() {
		_, err := io.Copy(writer, src)
		errChan <- err
	}()

	revDirection := getDirection(dst, src)
	revWriter := &loggingWriter{dst: src, server: server, logger: logger, capture: capture, dir: revDirection}

	// target to source
	go func() {
		_, err := io.Copy(revWriter, dst)
		errChan <- err
	}()
}

// getDirection returns the direction as a string
func getDirection(src, dst net.Conn) string {
	srcAddr := src.RemoteAddr().String()
	dstAddr := dst.RemoteAddr().String()
	return fmt.Sprintf("%s -> %s", srcAddr, dstAddr)
}

// Dial to the source ip, acting as a proxy between the client and real source by piping the data back and forth w/o interfering w it.
func HandlePassThrough(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	var err error
	handler := "tcp_proxy"

	srcAddr := conn.RemoteAddr().String()
	destAddr := md.Rule.Target

	host, _, err := net.SplitHostPort(destAddr)
	if err != nil {
		logger.Error("invalid address format", producer.ErrAttr(err))
		return nil
	}

	if ip := net.ParseIP(host); ip == nil {
		if _, err := net.LookupHost(host); err != nil {
			return fmt.Errorf("invalid host: %w", err)
		}
	}

	server := &passThroughServer{
		events: []parsedPassThrough{},
		conn:   conn,
		target: destAddr,
		source: srcAddr,
	}

	var capture bool
	if viper.GetBool("capture_traffic.enabled") {
		capture = true
	}

	defer func() {
		var events []parsedPassThrough
		if capture {
			events = server.events
		}
		if err := h.ProduceTCP("passthrough", conn, md, nil, events); err != nil {
			logger.Error("failed to produce passthrough message", producer.ErrAttr(err))
		}
		if err := conn.Close(); err != nil {
			logger.Error("failed to close incoming connection", slog.String("handler", handler), producer.ErrAttr(err))
		}
	}()

	if destAddr == "" {
		logger.Error("no target defined", slog.String("handler", handler))
		return nil
	}

	timeout := 5 * time.Second

	targetConn, err := net.DialTimeout("tcp", destAddr, timeout)
	if err != nil {
		logger.Error("failed to connect to the target", slog.String("handler", handler), slog.String("target", string(destAddr)), producer.ErrAttr(err))
		return nil
	}
	defer targetConn.Close()

	logger.Info("starting passthrough", slog.String("source", srcAddr), slog.String("target", string(destAddr)), slog.String("handler", handler))

	errChan := make(chan error, 2)

	go pipeBidirectional(conn, targetConn, server, logger, capture, errChan)

	// wait for either side to close
	if err := <-errChan; err != nil {
		log.Printf("connection closed: %v", err)
	}

	logger.Info("Passthrough completed successfully")
	return nil
}
