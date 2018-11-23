package glutton

import (
	"os"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// NewConsoleLogger creates the console logger fabric
func NewConsoleLogger(id string) zapcore.Core {
	atom := zap.NewAtomicLevel()
	consoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	consoleEncoder.AddString("sensorID", id)
	core := zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stdout), atom)
	var lvl zapcore.Level
	lvl.UnmarshalText([]byte(viper.GetString("log-level")))
	atom.SetLevel(lvl)
	return core
}

// NewLogger creates a logger instance
func NewLogger(id string) *zap.Logger {
	consoleCore := NewConsoleLogger(id)
	fileCore := NewFileLogger(id)
	teeCore := zapcore.NewTee(consoleCore, fileCore)
	return zap.New(teeCore)
}

// NewFileLogger creates a logger instance
func NewFileLogger(id string) zapcore.Core {
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
	core := zapcore.NewCore(fileEncoder, fileWriter, highPriority)
	return core
}
