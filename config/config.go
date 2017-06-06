package config

import (
	"fmt"
	"strconv"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Init initializes the configuration
func Init(confPath *string, logger *zap.Logger) (v *viper.Viper) {

	v = viper.New()

	// Loading config file
	v.SetConfigName("conf")
	v.AddConfigPath(*confPath)
	err := v.ReadInConfig()
	if err != nil {
		logger.Warn(fmt.Sprintf("[glutton ] no configuration file loaded - using defaults, error: %v", err))
	}
	validate(logger, v)

	// If no config is found, use the defaults
	v.SetDefault("glutton_server", 5000)
	v.SetDefault("proxy_tcp", 6000)
	v.SetDefault("rules_path", "rules/rules.yaml")
	v.SetDefault("gollumAddress", "http://gollum:gollum@localhost:9000")
	v.SetDefault("enableGollum", false)
	v.SetDefault("proxy_ssh", "tcp://localhost:22")

	logger.Info("[glutton ] configuration loaded successfully")
	return
}

func validate(logger *zap.Logger, v *viper.Viper) {

	ports := v.GetStringMapString("ports")
	if ports == nil {
		logger.Debug("[glutton ] Using default values for Ports")
	}

	for key, value := range ports {
		if key != "glutton_server" && key != "proxy_tcp" {
			logger.Error(fmt.Sprintf("[glutton ] invalid key found. key: %s", key))
			continue
		}
		if port, err := strconv.Atoi(value); err != nil {
			logger.Debug(fmt.Sprintf("[glutton ] using default value for port: %s", key))
		} else {
			v.Set(key, port)
		}
	}
	sshProxy := v.Get("proxy_ssh")
	if sshProxy != nil {
		p := sshProxy.([]interface{})
		v.Set("proxy_ssh", p[0].(string))
	} else {
		logger.Debug("[glutton ] using default value for proxy_ssh")
	}
	if v.GetString("log_path") == "" {
		logger.Debug("[glutton ] using default value for log_path")
	}
	if v.GetBool("enableGollum") == true {
		if v.GetString("gollumAddress") == "" {
			logger.Debug("[glutton ] using default value for gollum address")
		}
	}

}
