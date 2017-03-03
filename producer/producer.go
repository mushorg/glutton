package producer

import (
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
)

// Config for the producer
type Config struct {
	sensorID   string
	logger     *log.Logger
	httpAddr   *string // Address of HTTP consumer
	httpClient *http.Client
}

// Event is a struct for glutton events
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	SrcHost   string    `json:"srcHost"`
	SrcPort   string    `json:"srcPort"`
	DstPort   string    `json:"dstPort"`
	SensorID  string    `json:"sensorID"`
	Rule      string    `json:"rule"`
}

// Init initializes the producer
func Init(sensorID string, log *log.Logger, logHTTP *string) *Config {
	return &Config{
		sensorID:   sensorID,
		logger:     log,
		httpAddr:   logHTTP,
		httpClient: &http.Client{},
	}
}
