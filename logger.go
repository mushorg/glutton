package glutton

import (
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// NewLogger creates a logger instance
func NewLogger(id string) *zap.Logger {
	config := zap.NewProductionEncoderConfig()
	fileEncoder := zapcore.NewJSONEncoder(config)
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
	logger := zap.New(core)
	return logger
}
