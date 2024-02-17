package producer

import (
	"io"
	"log/slog"
	"os"

	"github.com/spf13/viper"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func ErrAttr(err error) slog.Attr {
	return slog.Any("error", err)
}

type TeeWriter struct {
	stdout *os.File
	file   io.Writer
}

func (t *TeeWriter) Write(p []byte) (n int, err error) {
	n, err = t.stdout.Write(p)
	if err != nil {
		return n, err
	}
	n, err = t.file.Write(p)
	return n, err
}

// NewLogger creates a logger instance
func NewLogger(id string) *slog.Logger {
	writer := &TeeWriter{
		stdout: os.Stdout,
		file: &lumberjack.Logger{
			Filename: viper.GetString("logpath"),
			MaxSize:  200,  // megabyte
			MaxAge:   356,  //days
			Compress: true, // disabled by default
		},
	}
	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{})
	return slog.New(handler.WithAttrs([]slog.Attr{slog.String("sensorID", id)}))
}
