package config

import (
	"testing"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func TestInitConf(t *testing.T) {
	logger, err := zap.NewProduction()
	if err != nil {
		t.Fatal(err)
	}
	viper.SetDefault("confpath", ".")
	if _, err = Init(logger); err != nil {
		t.Fatal(err)
	}
}
