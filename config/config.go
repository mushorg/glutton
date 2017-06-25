package config

import (
	"fmt"
	"strconv"

	"github.com/Unknwon/com"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type valueType int

const (
	boolean valueType = iota
	integer
	text
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
	// proxy_https defaults
	v.SetDefault("enableProxy", false)
	v.SetDefault("address", "127.0.0.1")
	v.SetDefault("httpPort", 1080)
	v.SetDefault("enableSSL", false)
	v.SetDefault("sslPort", 10433)
	v.SetDefault("certPath", "")
	v.SetDefault("keyPath", "")
	v.SetDefault("targetAddress", "http://www.notary-platform.com/")

	logger.Info("[glutton ] configuration loaded successfully")
	return
}

func validate(logger *zap.Logger, v *viper.Viper) {

	ports := v.GetStringMapString("ports")
	if ports == nil {
		logger.Debug("[glutton ] Using default values for Ports")
	} else {
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

	validateProxyHTTP(logger, v)
}

func validateProxyHTTP(logger *zap.Logger, v *viper.Viper) {
	validKeys := map[string]valueType{
		"enableproxy":   boolean,
		"address":       text,
		"httpport":      integer,
		"enablessl":     boolean,
		"sslport":       integer,
		"certpath":      text,
		"keypath":       text,
		"targetaddress": text,
	}

	proxy := v.GetStringMapString("proxy_http")
	if proxy == nil {
		logger.Debug("[glutton ] Using default values for http proxy")
	} else {
		for key, value := range proxy {
			vType, ok := validKeys[key]
			if !ok {
				logger.Error(fmt.Sprintf("[glutton ] invalid key found. key: %s", key))
				continue
			}

			switch vType {
			case boolean:
				if n, err := strconv.ParseBool(value); err != nil {
					logger.Debug(fmt.Sprintf("[glutton ] using default value for %s", key))
				} else {
					v.Set(key, n)
				}
				break
			case integer:
				if n, err := strconv.Atoi(value); err != nil {
					logger.Debug(fmt.Sprintf("[glutton ] using default value for %s", key))
				} else {
					v.Set(key, n)
				}
				break
			case text:
				if len(value) < 5 {
					logger.Debug(fmt.Sprintf("[glutton ] using default value for %s", key))
					continue

				}
				if (key == "certPath" || key == "keyPath") && !com.IsFile(value) {
					logger.Debug(fmt.Sprintf("[glutton ] using default value for %s", key))
					continue
				} else {
					v.Set(key, value)
				}

				break
			}
		}
	}
}
