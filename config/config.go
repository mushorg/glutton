package config

import (
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Init initializes the configuration
func Init(logger *zap.Logger) (v *viper.Viper, err error) {
	v = viper.New()
	// Loading config file
	v.SetConfigName("conf")
	v.AddConfigPath(viper.GetString("confpath"))
	if err = v.ReadInConfig(); err != nil {
		return
	}
	// If no config is found, use the defaults
	v.SetDefault("glutton_server", 5000)
	v.SetDefault("rules_path", "rules/rules.yaml")
	v.SetDefault("gollumAddress", "http://gollum:gollum@localhost:9000")
	v.SetDefault("enableGollum", false)

	logger.Debug("configuration loaded successfully", zap.String("reporter", "glutton"))
	return
}
