package glutton

import (
	// "errors"
	"fmt"
	// "github.com/Unknwon/com"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func initLogger(logPath *string, id string, debug *bool) (*zap.Logger, error) {
	fmt.Println("[glutton ] log path: ", *logPath)

	var cfg zap.Config
	// logFile := *logPath + ".log"
	// if !com.IsDir(logFile) {
	cfg = zap.NewProductionConfig()
	// cfg.OutputPaths = []string{logFile}
	// } else {
	// 	err := errors.New("[glutton ] file name is missing in log path")
	// 	return nil, err
	// }

	cfg.InitialFields = map[string]interface{}{
		"sensorID": id,
	}

	if *debug {
		cfg.Level.SetLevel(zapcore.DebugLevel)
	}

	logger, err := cfg.Build()
	return logger, err
}

// TODO: add connection information to log message
/*
func (g *Glutton) addFeilds(srcHost, srcPort, dstHost, rule string, dstPort uint16, connKey [2]uint64) *zap.Logger {
	return g.logger.WithOptions(zap.Fields(
		zap.String("srcHost", srcHost),
		zap.String("srcPort", srcPort),
		zap.String("dstHost", dstHost),
		zap.Uint16("dstPort", dstPort),
		zap.String("rule", rule),
		zap.Any("connKey", connKey),
	))
}
*/
