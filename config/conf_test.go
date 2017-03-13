package config

import (
	"testing"

	log "github.com/Sirupsen/logrus"
)

func TestInitConf(t *testing.T) {
	logger := log.New()
	Init(".", logger)
}
