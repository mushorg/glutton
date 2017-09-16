package glutton

import (
	"errors"
	"github.com/Unknwon/com"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"strconv"
)

func initLogger(logPath *string, id string, debug *string) (*zap.Logger, error) {

	var cfg zap.Config
	if !com.IsDir(*logPath) {
		cfg = zap.NewProductionConfig()
		cfg.ErrorOutputPaths = []string{*logPath + ".err"}
		cfg.OutputPaths = []string{*logPath}
	} else {
		err := errors.New("[glutton ] file name is missing in log path")
		return nil, err
	}

	cfg.InitialFields = map[string]interface{}{
		"sensorID": id,
	}

	check_debug, err := strconv.ParseBool(*debug)
	if err != nil {
		return nil, err
	}
	if check_debug {
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
