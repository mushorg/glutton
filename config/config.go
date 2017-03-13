package config

import (
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
)

// Init initializes the configuration
func Init(confPath string, logger *log.Logger) (v *viper.Viper) {

	v = viper.New()

	// Loading config file
	v.SetConfigName("conf")
	v.AddConfigPath(confPath)
	err := v.ReadInConfig()
	if err != nil {
		logger.Errorf("[glutton ] No configuration file loaded - using defaults: %s", err)
	}
	validate(logger, v)

	// If no config is found, use the defaults
	v.SetDefault("glutton_server", 5000)
	v.SetDefault("proxy_tcp", 6000)
	v.SetDefault("rules_path", "rules/rules.yaml")
	v.SetDefault("gollum", "http://gollum:gollum@localhost:9000")
	v.SetDefault("proxy_ssh", "tcp://localhost:22")

	logger.Debug("[glutton ] Configuration file loaded successfully")
	return
}

func validate(logger *log.Logger, v *viper.Viper) {

	ports := v.GetStringMapString("ports")
	if ports == nil {
		logger.Debug("[glutton ] Using default values for Ports")
	}

	for key, value := range ports {
		if key != "glutton_server" && key != "proxy_tcp" {
			logger.Errorf("[glutton ] Invalid key found: %s", key)
			continue
		}
		if port, err := strconv.Atoi(value); err != nil {
			logger.Debugf("[glutton ] Using default value for ports:%s", key)
		} else {
			v.Set(key, port)
		}
	}
	sshProxy := v.Get("proxy_ssh")
	if sshProxy != nil {
		p := sshProxy.([]interface{})
		v.Set("proxy_ssh", p[0].(string))
	} else {
		logger.Debug("[glutton ] Using default value for proxy_ssh")
	}

	if v.GetString("rules_path") == "" {
		logger.Debug("[glutton ] Using default value for rules_path")
	}
	if v.GetString("log_path") == "" {
		logger.Debug("[glutton ] Using default value for log_path")
	}
	if v.GetString("gollum") == "" {
		logger.Debug("[glutton ] Using default value for gollum")
	}
}
