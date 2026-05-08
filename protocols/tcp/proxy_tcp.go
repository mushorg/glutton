package tcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/spf13/viper"
)

const handlerName = "proxy_tcp"

// a proxy connection event sent to producers
type event struct {
	Direction   string `json:"direction,omitempty"`
	Payload     []byte `json:"payload,omitempty"`
	PayloadHash string `json:"payload_hash,omitempty"` // Used for easier identification, can remove
	Bytes       int64  `json:"bytes,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

// holds a proxy connection metadata
type session struct {
	source      string
	target      string
	producer    bool
	idleTimeout time.Duration
	payloadSize int
}

// reader wrapps the source connection for idle deadline.
type reader struct {
	conn net.Conn
	idle time.Duration
	name string
}

func (r reader) Read(p []byte) (int, error) {
	if r.idle > 0 {
		if err := r.conn.SetReadDeadline(time.Now().Add(r.idle)); err != nil {
			return 0, fmt.Errorf("%s set read deadline: %w", r.name, err)
		}
	}

	n, err := r.conn.Read(p)
	// EOF is the normal way a stream says there are no more bytes to read.
	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("%s read: %w", r.name, err)
	}
	return n, err
}

// writer wraps the destination connection for logging and idle deadline
type writer struct {
	conn    net.Conn
	session *session
	logger  interfaces.Logger
	dir     string
	name    string

	written int64
	payload []byte
}

func (w *writer) Write(p []byte) (int, error) {
	if w.session.idleTimeout > 0 {
		if err := w.conn.SetWriteDeadline(time.Now().Add(w.session.idleTimeout)); err != nil {
			return 0, fmt.Errorf("%s set write deadline: %w", w.name, err)
		}
	}

	n, err := w.conn.Write(p)
	if err != nil {
		w.logger.Debug("proxy writer returned error", logAttrs(
			slog.String("function", "writer.Write"),
			slog.String("direction", w.dir),
			slog.Int("bytes_written", n),
			producer.ErrAttr(err),
		)...)
		return n, fmt.Errorf("%s write: %w", w.name, err)
	}

	// A Write can partially succeed. Only p[:n] reached the destination, so only
	// those bytes should affect logs, byte counts, and capture samples.
	if n > 0 {
		written := p[:n]
		w.written += int64(n)
		w.session.logPayload(w.dir, written, w.logger)
		w.storePayload(written)
	}

	if n != len(p) {
		return n, fmt.Errorf("%s short write: %w", w.name, io.ErrShortWrite)
	}

	return n, nil
}

// emits a structured log for connection metadata including raw payload
func (s *session) logPayload(direction string, data []byte, logger interfaces.Logger) {
	if len(data) == 0 {
		return
	}

	// always log transfer metadata excluding raw service data.
	fields := logAttrs(
		slog.String("direction", direction),
		slog.Int("length", len(data)),
		slog.String("payload_hash", fmt.Sprintf("%x", sha256.Sum256(data))),
	)

	// when caputure enabled then include raw payload data to logs
	if s.producer && s.payloadSize > 0 {
		sample := data
		truncated := false
		if len(sample) > s.payloadSize {
			sample = sample[:s.payloadSize]
			truncated = true
		}

		if isLikelyText(sample) {
			fields = append(fields, slog.String("payload", string(sample)))
		} else {
			fields = append(fields, slog.String("hex", hex.EncodeToString(sample)))
		}
		fields = append(fields, slog.Bool("payload_truncated", truncated))
	}

	logger.Info("proxy_tcp payload_transferred", fields...)
}

// storePayload stores a bounded sample of written bytes for producer output.
func (w *writer) storePayload(p []byte) {
	if !w.session.producer || w.session.payloadSize <= 0 {
		return
	}

	if len(w.payload) >= w.session.payloadSize {
		return
	}

	remaining := w.session.payloadSize - len(w.payload)
	if len(p) > remaining {
		p = p[:remaining]
	}
	w.payload = append(w.payload, p...)
}

// event converts the stored payload writer-owned capture sample into a producer event.
func (w *writer) event() *event {
	if !w.session.producer || len(w.payload) == 0 {
		return nil
	}

	payload := append([]byte(nil), w.payload...)
	hash := sha256.Sum256(payload)
	return &event{
		Direction:   w.dir,
		Payload:     payload,
		PayloadHash: fmt.Sprintf("%x", hash[:]),
		Bytes:       w.written,
		Truncated:   w.written > int64(len(payload)),
	}
}

// logAttrs adds common structured log fields to every proxy_tcp log.
func logAttrs(fields ...any) []any {
	base := []any{
		slog.String("handler", handlerName),
	}
	return append(base, fields...)
}

// isLikelyText checks whether a byte slice is mostly printable text.
func isLikelyText(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	printable := 0
	for _, b := range data {
		if b >= 32 && b <= 126 || b == '\n' || b == '\r' || b == '\t' {
			printable++
		}
	}

	// Require more than 80% printable bytes so mostly-binary payloads stay as hex.
	return (printable*100)/len(data) > 80
}

// pipeResult is the completion report from one directional pipe.
type pipeResult struct {
	dir   string
	bytes int64
	event *event
	err   error
}

// pipe copies bytes in one direction and sends a pipeResult when that direction ends.
func pipe(done chan<- pipeResult, dst, src net.Conn, session *session, logger interfaces.Logger) {
	dir := getDirection(src, dst)
	writer := &writer{
		conn:    dst,
		session: session,
		logger:  logger,
		dir:     dir,
		name:    dir + " dst",
	}

	reader := reader{
		conn: src,
		idle: session.idleTimeout,
		name: dir + " src",
	}

	_, err := io.Copy(writer, reader)

	// Tell the destination peer there will be no more bytes from this direction.
	if closeErr := finishWriteSide(dst, logger, dir); closeErr != nil && err == nil {
		err = fmt.Errorf("%s close write: %w", dir, closeErr)
	}

	// Stop reading from the source side after this direction has completed.
	if closeErr := finishReadSide(src, logger, dir); closeErr != nil && err == nil {
		err = fmt.Errorf("%s close read: %w", dir, closeErr)
	}

	done <- pipeResult{
		dir:   dir,
		bytes: writer.written,
		event: writer.event(),
		err:   err,
	}
}

// pipeBothWays starts proxy connection between client and target
func pipeBothWays(client, target net.Conn, session *session, logger interfaces.Logger) []pipeResult {
	logger.Debug("starting proxy bidirectional copy", logAttrs(
		slog.String("function", "pipeBothWays"),
		slog.String("source", session.source),
		slog.String("target", session.target),
	)...)

	done := make(chan pipeResult, 2)
	go pipe(done, target, client, session, logger)
	go pipe(done, client, target, session, logger)

	// Wait for both directions before returning
	return []pipeResult{<-done, <-done}
}

// eventsFromResults extracts captured producer events from completed pipe results.
func eventsFromResults(results []pipeResult) []event {
	events := make([]event, 0, len(results))
	for _, result := range results {
		if result.event != nil {
			events = append(events, *result.event)
		}
	}
	return events
}

func getDirection(src, dst net.Conn) string {
	return fmt.Sprintf("%s -> %s", src.RemoteAddr().String(), dst.RemoteAddr().String())
}

// logResult records the outcome from one directional pipe.
func logResult(logger interfaces.Logger, result pipeResult) {
	fields := logAttrs(
		slog.String("function", "logResult"),
		slog.String("direction", result.dir),
		slog.Int64("bytes", result.bytes),
	)

	// Include capture metadata without logging raw bytes again.
	if result.event != nil {
		fields = append(fields,
			slog.Int("captured_bytes", len(result.event.Payload)),
			slog.String("payload_hash", result.event.PayloadHash),
			slog.Bool("truncated", result.event.Truncated),
		)
	}

	// Attach the copy error before deciding the log level.
	if result.err != nil {
		fields = append(fields, producer.ErrAttr(result.err))
	}

	if expectedPipeError(result.err) {
		logger.Debug("proxy pipe completed", fields...)
	} else {
		logger.Error("proxy pipe failed", fields...)
	}
}

// expectedPipeError classifies normal network shutdown results from io.Copy.
func expectedPipeError(err error) bool {
	if err == nil {
		return true
	}

	// EOF and "use of closed network connection" are expected when scanners or
	// targets close sockets during normal request/response exchanges.
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ENOTCONN) {
		return true
	}

	// Deadline timeouts can be created by reader or shutdown fallbacks
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

// Use for used for half-closing a write side, if unavailable, it uses a deadline
func finishWriteSide(conn net.Conn, logger interfaces.Logger, dir string) error {
	if cw, ok := conn.(closeWriter); ok {
		logger.Debug("closing proxy write side", logAttrs(
			slog.String("function", "finishWriteSide"),
			slog.String("direction", dir),
			slog.String("address", conn.RemoteAddr().String()),
		)...)
		if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
		return nil
	}

	// Non-TCP net.Conn implementations may not support half-close.
	logger.Debug("setting proxy write shutdown deadline", logAttrs(
		slog.String("function", "finishWriteSide"),
		slog.String("direction", dir),
		slog.String("address", conn.RemoteAddr().String()),
	)...)
	return conn.SetDeadline(time.Now().Add(2 * time.Second))
}

// Use for used for half-closing a read side, if unavailable, it uses a deadline
func finishReadSide(conn net.Conn, logger interfaces.Logger, dir string) error {
	if cr, ok := conn.(closeReader); ok {
		logger.Debug("closing proxy read side", logAttrs(
			slog.String("function", "finishReadSide"),
			slog.String("direction", dir),
			slog.String("address", conn.RemoteAddr().String()),
		)...)
		if err := cr.CloseRead(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
		return nil
	}

	// Non-TCP net.Conn implementations may not support CloseRead.
	logger.Debug("setting proxy read shutdown deadline", logAttrs(
		slog.String("function", "finishReadSide"),
		slog.String("direction", dir),
		slog.String("address", conn.RemoteAddr().String()),
	)...)
	return conn.SetReadDeadline(time.Now().Add(2 * time.Second))
}

// It is best-effort to enables TCP keepalive for real TCP connections
func setKeepAlive(conn net.Conn, logger interfaces.Logger, name string) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	if err := tcpConn.SetKeepAlive(true); err != nil {
		logger.Debug("failed to enable proxy keepalive", logAttrs(
			slog.String("function", "setKeepAlive"),
			slog.String("name", name),
			producer.ErrAttr(err),
		)...)
	}
}

func stopProxyOnCancel(ctx context.Context, client, target net.Conn, logger interfaces.Logger) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			logger.Debug("closing proxy connections after context cancellation", logAttrs(
				slog.String("function", "stopProxyOnCancel"),
				producer.ErrAttr(ctx.Err()),
			)...)
			closeProxyConn(client, logger, "client")
			closeProxyConn(target, logger, "target")
		case <-done:
		}
	}()

	return func() {
		close(done)
	}
}

func closeProxyConn(conn net.Conn, logger interfaces.Logger, name string) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Debug("failed to close proxy connection", logAttrs(
			slog.String("function", "closeProxyConn"),
			slog.String("name", name),
			producer.ErrAttr(err),
		)...)
	}
}

func HandleProxyTCP(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	srcAddr := conn.RemoteAddr().String()

	logger.Debug("entered proxy handler", logAttrs(
		slog.String("function", "HandleProxyTCP"),
		slog.String("source", srcAddr),
	)...)
	defer logger.Debug("leaving proxy handler", logAttrs(
		slog.String("function", "HandleProxyTCP"),
		slog.String("source", srcAddr),
	)...)

	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Error("failed to close incoming connection", logAttrs(
				slog.String("function", "HandleProxyTCP"),
				producer.ErrAttr(err),
			)...)
		}
	}()

	// If missing metadata, close without panick
	if md.Rule == nil {
		logger.Error("missing proxy_tcp rule metadata", logAttrs(
			slog.String("function", "HandleProxyTCP"),
		)...)
		return nil
	}

	// If it is missing here, the handler cannot safely dial anything
	if md.Rule.ProxyTarget == nil || md.Rule.ProxyTarget.DialAddress == "" {
		logger.Error("missing proxy_tcp target metadata", logAttrs(
			slog.String("function", "HandleProxyTCP"),
		)...)
		return nil
	}
	destAddr := md.Rule.ProxyTarget.DialAddress

	session := &session{
		source:      srcAddr,
		target:      destAddr,
		producer:    viper.GetBool("capture_traffic.enabled"),
		idleTimeout: time.Duration(viper.GetInt("conn_timeout")) * time.Second,
		payloadSize: viper.GetInt("max_tcp_payload"),
	}

	var results []pipeResult

	// capture is enabled, produces one final proxy_tcp event after connection closes.
	defer func() {
		var events []event
		if session.producer {
			events = eventsFromResults(results)
		}
		if err := h.ProduceTCP("proxy_tcp", conn, md, nil, events); err != nil {
			logger.Error("failed to produce proxy_tcp message", logAttrs(
				slog.String("function", "HandleProxyTCP"),
				producer.ErrAttr(err),
			)...)
		}
	}()

	// Enable keepalive for the client side
	setKeepAlive(conn, logger, "client")

	dialerTimeout := time.Duration(viper.GetInt("dial_timeout")) * time.Second
	dialer := net.Dialer{Timeout: dialerTimeout}
	targetConn, err := dialer.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		logger.Error("failed to connect to the target", logAttrs(
			slog.String("function", "HandleProxyTCP"),
			slog.String("target", destAddr),
			producer.ErrAttr(err),
		)...)
		return nil
	}
	defer targetConn.Close()
	stopCancelWatcher := stopProxyOnCancel(ctx, conn, targetConn, logger)
	defer stopCancelWatcher()

	// Enable keepalive for the target side
	setKeepAlive(targetConn, logger, "target")

	// At this point both sockets are open. The next step is full-duplex copying.
	logger.Debug("starting proxy tcp", logAttrs(
		slog.String("function", "HandleProxyTCP"),
		slog.String("source", srcAddr),
		slog.String("target", destAddr),
		slog.Duration("idle_timeout", session.idleTimeout),
		slog.Int("payload_size", session.payloadSize),
	)...)

	// pipeBothWays waits for the success / failure of proxy session and return results
	results = pipeBothWays(conn, targetConn, session, logger)
	for _, result := range results {
		logResult(logger, result)
	}

	logger.Debug("proxy tcp completed successfully", logAttrs(
		slog.String("function", "HandleProxyTCP"),
	)...)
	return nil
}
