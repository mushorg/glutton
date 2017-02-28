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

// Address provides remote address to producer
type Address struct {
	logger   *log.Logger
	httpAddr *string // Address of HTTP consumer
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

func NewAddress(log *log.Logger, logHTTP *string) *Address {
	return &Address{
		logger:   log,
		httpAddr: logHTTP,
	}
}

// Send logs to web socket
func (addr *Address) LogHTTP(host, port, dstPort, sensorID, rule string) (err error) {
	if *addr.httpAddr == "" {
		return fmt.Errorf("[glutton ] Address is nil in HTTP log producer.", nil)
	}

	client := &http.Client{}
	conn, err := url.Parse(*addr.httpAddr)
	if err != nil {
		return
	}
	event := Event{
		Timestamp: time.Now().UTC(),
		SrcHost:   host,
		SrcPort:   port,
		DstPort:   dstPort,
		SensorID:  sensorID,
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
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	addr.logger.Debugf("[glutton  ] response: %s", resp.Status)
	return
}
