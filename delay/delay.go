package delay

import (
	"math/rand"
	"time"
)

type DelayRange struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

type PortDelay struct {
	Port      int      `yaml:"port"`
	Min       int      `yaml:"min"`
	Max       int      `yaml:"max"`
	Protocols []string `yaml:"protocols"`
}

type DelayConfig struct {
	Global  DelayRange  `yaml:"global"`
	PerPort []PortDelay `yaml:"per_port"`
}

func NewDelayHandler(config DelayConfig) *DelayHandler {
	return &DelayHandler{config: config}
}

type DelayHandler struct {
	config DelayConfig
}

func (h *DelayHandler) GetDelay(port int, protocol string) time.Duration {
	// Check port specific delay
	for _, pd := range h.config.PerPort {
		if pd.Port == port {
			for _, p := range pd.Protocols {
				if p == protocol {
					return time.Duration(rand.Intn(pd.Max-pd.Min+1)+pd.Min) * time.Millisecond
				}
			}
		}
	}

	// Fall back to global delay
	return time.Duration(rand.Intn(h.config.Global.Max-h.config.Global.Min+1)+h.config.Global.Min) * time.Millisecond
}
