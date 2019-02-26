package glutton

import (
	"os"
	"reflect"
	"testing"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func TestNewConsoleLogger(t *testing.T) {

	mockAtom := zap.NewAtomicLevel()
	mockConsoleEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	mockConsoleEncoder.AddString("sensorID", "test_id")
	mockCore := zapcore.NewCore(mockConsoleEncoder, zapcore.Lock(os.Stdout), mockAtom)

	if reflect.TypeOf(NewConsoleLogger("test_id")) != reflect.TypeOf(mockCore) {
		t.Fatal("Failed to create NewConsoleLogger instance")
	}

}

func TestNewLogger(t *testing.T) {
	var zapLoggerInstance *zap.Logger
	if reflect.TypeOf(NewLogger("test_id")) != reflect.TypeOf(zapLoggerInstance) {
		t.Fatal("Failed to create a Logger instance")
	}
}

func TestNewFileLogger(t *testing.T) {

	mockFileEncoder := zapcore.NewJSONEncoder(
		zap.NewProductionEncoderConfig(),
	)
	mockFileEncoder.AddString("sensorID", "test_id")
	mockHighPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= zapcore.InfoLevel
	})
	mockFileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename: viper.GetString("logpath"),
		MaxSize:  200,  // megabyte
		MaxAge:   356,  //days
		Compress: true, // disabled by default
	})
	mockCore := zapcore.NewCore(mockFileEncoder, mockFileWriter, mockHighPriority)
	if reflect.TypeOf(NewFileLogger("test_id")) != reflect.TypeOf(mockCore) {
		t.Fatal("Failed to create File Logger instance")
	}
}
