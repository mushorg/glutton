package producer

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/fw42/go-hpfeeds"
	"github.com/kung-foo/freki"
	"github.com/spf13/viper"
)

// Producer for the producer
type Producer struct {
	sensorID   string
	httpClient *http.Client
	hpfClient  hpfeeds.Hpfeeds
	hpfChannel chan []byte
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

func makeEvent(conn net.Conn, md *freki.Metadata, payload []byte, sensorID string) (*Event, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	ck := freki.NewConnKeyByString(host, port)
	event := Event{
		Timestamp: time.Now().UTC(),
		SrcHost:   host,
		SrcPort:   port,
		DstPort:   uint16(md.TargetPort),
		SensorID:  sensorID,
		Rule:      md.Rule.String(),
		ConnKey:   ck,
		Payload:   base64.StdEncoding.EncodeToString(payload),
	}
	return &event, nil
}

// New initializes the producers
func New(sensorID string) (*Producer, error) {
	producer := &Producer{
		sensorID:   sensorID,
		httpClient: &http.Client{},
	}
	if viper.GetBool("producers.hpfeeds.enabled") {
		producer.hpfClient = hpfeeds.NewHpfeeds(
			viper.GetString("producers.hpfeeds.host"),
			viper.GetInt("producers.hpfeeds.port"),
			viper.GetString("producers.hpfeeds.ident"),
			viper.GetString("producers.hpfeeds.auth"),
		)
		if err := producer.hpfClient.Connect(); err != nil {
			return producer, err
		}
		producer.hpfChannel = make(chan []byte)
		producer.hpfClient.Publish(viper.GetString("producers.hpfeeds.channel"), producer.hpfChannel)
	}
	return producer, nil
}

// Log is a meta caller for all producers
func (p *Producer) Log(conn net.Conn, md *freki.Metadata, payload []byte) error {
	event, err := makeEvent(conn, md, payload, p.sensorID)
	if err != nil {
		return err
	}
	if viper.GetBool("producers.hpfeeds.enabled") {
		if err := p.LogHPFeeds(event); err != nil {
			return err
		}
	}
	if viper.GetBool("producers.gollum.enabled") {
		if err := p.LogHTTP(event); err != nil {
			return err
		}
	}
	return nil
}

// LogHPFeeds logs an event to a hpfeeds broker
func (p *Producer) LogHPFeeds(event *Event) (err error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(event); err != nil {
		return err
	}
	p.hpfChannel <- buf.Bytes()
	return nil
}

// LogHTTP send logs to HTTP endpoint
func (p *Producer) LogHTTP(event *Event) (err error) {
	url, err := url.Parse(viper.GetString("producers.gollum.remote"))
	if err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", url.Scheme+"://"+url.Host, bytes.NewBuffer(data))
	if err != nil {
		return
	}
	password, _ := url.User.Password()
	req.SetBasicAuth(url.User.Username(), password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return
	}
	if err = resp.Body.Close(); err != nil {
		return
	}
	return
}
