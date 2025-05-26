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
	handlerOptions := &slog.HandlerOptions{}
	debug := viper.GetBool("debug")
	switch debug {
	case true:
		handlerOptions.Level = slog.Leveler(slog.LevelDebug)
	default:
		handlerOptions.Level = slog.Leveler(slog.LevelInfo)
	}
	handler := slog.NewJSONHandler(writer, handlerOptions)
	return slog.New(handler.WithAttrs([]slog.Attr{slog.String("sensorID", id)}))
}
