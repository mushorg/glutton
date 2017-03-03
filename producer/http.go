package producer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

// LogHTTP send logs to web socket
func (conf *Config) LogHTTP(host, port, dstPort, rule string) (err error) {
	if *conf.httpAddr == "" {
		return fmt.Errorf("[glutton ] Address is nil in HTTP log producer")
	}

	conn, err := url.Parse(*conf.httpAddr)
	if err != nil {
		return
	}
	event := Event{
		Timestamp: time.Now().UTC(),
		SrcHost:   host,
		SrcPort:   port,
		DstPort:   dstPort,
		SensorID:  conf.sensorID,
		Rule:      rule,
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", conn.Scheme+"://"+conn.Host, bytes.NewBuffer(data))
	if err != nil {
		return
	}
	password, _ := conn.User.Password()
	req.SetBasicAuth(conn.User.Username(), password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := conf.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	conf.logger.Debugf("[glutton ] gollum response: %s", resp.Status)
	return
}
