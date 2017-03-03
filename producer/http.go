package producer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

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
