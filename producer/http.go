package producer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/kung-foo/freki"
)

// Config for the producer
type Config struct {
	sensorID   string
	httpAddr   string // Address of HTTP consumer
	httpClient *http.Client
}

// Event is a struct for glutton events
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	SrcHost   string    `json:"srcHost"`
	SrcPort   string    `json:"srcPort"`
	DstPort   uint16    `json:"dstPort"`
	SensorID  string    `json:"sensorID"`
	Rule      string    `json:"rule"`
	ConnKey   [2]uint64 `json:"connKey"`
	Payload   string    `json:"payload"`
	Action    string    `json:"action"`
}

// Init initializes the producer
func Init(sensorID string, logHTTP string) *Config {
	return &Config{
		sensorID:   sensorID,
		httpAddr:   logHTTP,
		httpClient: &http.Client{},
	}
}

// LogHTTP send logs to HTTP endpoint
func (conf *Config) LogHTTP(conn net.Conn, md *freki.Metadata, payload []byte, action string) (err error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return
	}
	connKey := freki.NewConnKeyByString(host, port)
	if conf.httpAddr == "" {
		return fmt.Errorf("[glutton ] Address is nil in HTTP log producer")
	}

	gConn, err := url.Parse(conf.httpAddr)
	if err != nil {
		return
	}
	event := Event{
		Timestamp: time.Now().UTC(),
		SrcHost:   host,
		SrcPort:   port,
		DstPort:   uint16(md.TargetPort),
		SensorID:  conf.sensorID,
		Rule:      md.Rule.String(),
		ConnKey:   connKey,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Action:    action,
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", gConn.Scheme+"://"+gConn.Host, bytes.NewBuffer(data))
	if err != nil {
		return
	}
	password, _ := gConn.User.Password()
	req.SetBasicAuth(gConn.User.Username(), password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := conf.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return
}
