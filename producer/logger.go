package producer

import (
	"os"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// NewLogger creates a logger instance
func NewLogger(id string) *zap.Logger {
	consoleCore := newConsoleLogger(id)
	fileCore := newFileLogger(id)
	teeCore := zapcore.NewTee(consoleCore, fileCore)
	return zap.New(teeCore)
}

// newConsoleLogger creates the console logger fabric
func newConsoleLogger(id string) zapcore.Core {
	atom := zap.NewAtomicLevel()
	var lvl zapcore.Level
	lvl.UnmarshalText([]byte(viper.GetString("log-level")))
	atom.SetLevel(lvl)
	consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	consoleEncoder.AddString("sensorID", id)
	return zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stdout), atom)
}

// newFileLogger creates a logger instance
func newFileLogger(id string) zapcore.Core {
	fileEncoder := zapcore.NewJSONEncoder(
		zap.NewProductionEncoderConfig(),
	)
	fileEncoder.AddString("sensorID", id)
	highPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.InfoLevel
	})
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename: viper.GetString("logpath"),
		MaxSize:  200,  // megabyte
		MaxAge:   356,  //days
		Compress: true, // disabled by default
	})
	return zapcore.NewCore(fileEncoder, fileWriter, highPriority)
}
