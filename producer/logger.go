package producer

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"

	"github.com/mushorg/glutton/protocols/guard"
	"github.com/spf13/viper"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func ErrAttr(err error) slog.Attr {
	return slog.Any("error", err)
}

type TeeWriter struct {
	stdout io.Writer
	file   io.Writer // nil when logging to stdout only
}

func (t *TeeWriter) Write(p []byte) (n int, err error) {
	n, err = t.stdout.Write(p)
	if err != nil || t.file == nil {
		return n, err
	}
	n, err = t.file.Write(p)
	return n, err
}

// logFile returns the rotating writer for path, or nil when path is not a
// log file: empty, os.DevNull (the --logpath default), or an existing
// non-regular file such as a device or pipe. lumberjack rotates by renaming
// the file and creating a new regular one, so on /dev/null it replaced the
// device with a growing file in RAM-backed devtmpfs that every process on
// the host then wrote into.
func logFile(path string) io.Writer {
	if path == "" || path == os.DevNull {
		return nil
	}
	if fi, err := os.Stat(path); err == nil && !fi.Mode().IsRegular() {
		return nil
	}
	return &lumberjack.Logger{
		Filename: path,
		MaxSize:  200,  // megabyte
		MaxAge:   356,  //days
		Compress: true, // disabled by default
	}
}

// NewLogger creates a logger instance
func NewLogger(id string) *slog.Logger {
	writer := &TeeWriter{
		stdout: os.Stdout,
		file:   logFile(viper.GetString("logpath")),
	}
	handlerOptions := &slog.HandlerOptions{}
	debug := viper.GetBool("debug")
	switch debug {
	case true:
		handlerOptions.Level = slog.Leveler(slog.LevelDebug)
	default:
		handlerOptions.Level = slog.Leveler(slog.LevelInfo)
	}
	handler := slog.NewJSONHandler(writer, handlerOptions)
	return slog.New(&sourceLimitHandler{next: handler.WithAttrs([]slog.Attr{slog.String("sensorID", id)})})
}

// logLimit is the log_limit budget; nil until SetLogLimit, so nothing is
// dropped while the config loads.
var logLimit atomic.Pointer[guard.Guard]

// SetLogLimit sets the budget that bounds Info lines per source.
func SetLogLimit(g *guard.Guard) {
	logLimit.Store(g)
}

// sourceLimitHandler drops Info records with a src_ip attribute once that
// source is over the log_limit budget, so a flood does not log a line per
// connection. Other levels and records without src_ip always pass.
type sourceLimitHandler struct {
	next slog.Handler
}

func (h *sourceLimitHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *sourceLimitHandler) Handle(ctx context.Context, r slog.Record) error {
	g := logLimit.Load()
	if g == nil || r.Level != slog.LevelInfo {
		return h.next.Handle(ctx, r)
	}
	var ip net.IP
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "src_ip" {
			ip = net.ParseIP(a.Value.String())
			return false
		}
		return true
	})
	if ip == nil {
		return h.next.Handle(ctx, r)
	}
	d := g.Allow(ip, 0)
	if d.Allowed {
		return h.next.Handle(ctx, r)
	}
	if !d.First {
		return nil
	}
	warn := slog.NewRecord(r.Time, slog.LevelWarn, "Dropping log lines over the log budget", r.PC)
	warn.AddAttrs(
		slog.String("limit", string(d.Limit)),
		slog.String("src_ip", ip.String()),
		slog.String("dropped_msg", r.Message),
		slog.String("reporter", "glutton"),
	)
	return h.next.Handle(ctx, warn)
}

func (h *sourceLimitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &sourceLimitHandler{next: h.next.WithAttrs(attrs)}
}

func (h *sourceLimitHandler) WithGroup(name string) slog.Handler {
	return &sourceLimitHandler{next: h.next.WithGroup(name)}
}
