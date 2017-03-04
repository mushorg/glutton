package config

import (
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/spf13/viper"
)

func Init(logger *log.Logger) (v *viper.Viper) {

	v = viper.New()

	// Loading config file
	v.SetConfigName("conf")
	v.AddConfigPath("../")
	v.AddConfigPath("$GOPATH/src/github.com/mushorg/glutton/config/")
	v.AddConfigPath("config/")
	err := v.ReadInConfig()
	if err != nil {
		logger.Error("[glutton ] No configuration file loaded - using defaults")
	}
	validate(logger, v)

	// If no config is found, use the defaults
	v.SetDefault("gluttonServer", 5000)
	v.SetDefault("tcpProxy", 6000)
	v.SetDefault("rulesPath", "rules/rules.yaml")
	v.SetDefault("logPath", "/dev/null")
	v.SetDefault("gollum", "http://gollum:gollum@localhost:9000")
	v.SetDefault("sshProxy", "tcp://localhost:22")

	logger.Debug("[glutton ] Configuration file loaded successfully")
	return
}

func validate(logger *log.Logger, v *viper.Viper) {

	ports := v.GetStringMapString("ports")
	if ports == nil {
		logger.Debug("[glutton ] Using default values for Ports")
	}

	for key, value := range ports {
		if key != "glutton" && key != "tcpproxy" {
			logger.Errorf("[glutton ] Invalid key found: %s", key)
			continue
		}
		if port, err := strconv.Atoi(value); err != nil {
			logger.Debugf("[glutton ] Using default value for ports:%s", key)
		} else {
			v.Set(key, port)
		}
	}
	sshProxy := v.Get("sshProxy")
	if sshProxy != nil {
		p := sshProxy.([]interface{})
		v.Set("sshProxy", p[0].(string))
	} else {
		logger.Debug("[glutton ] Using default value for sshProxy")
	}

	if v.GetString("rulesPath") == "" {
		logger.Debug("[glutton ] Using default value for rulesPath")
	}
	if v.GetString("logPath") == "" {
		logger.Debug("[glutton ] Using default value for logPath")
	}
	if v.GetString("gollum") == "" {
		logger.Debug("[glutton ] Using default value for gollum")
	}
}
