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
	"github.com/mushorg/glutton/scanner"
	"github.com/spf13/viper"
)

const (
	httpTimeout = 10 * time.Second
	tlsTimeout  = 5 * time.Second
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
	Scanner   string    `json:"scanner"`
}

func makeEvent(conn net.Conn, md *freki.Metadata, payload []byte, sensorID string) (*Event, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}

	_, scannerName, err := scanner.IsScanner(net.ParseIP(host))
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
		Scanner:   scannerName,
	}
	return &event, nil
}

// New initializes the producers
func New(sensorID string) (*Producer, error) {
	producer := &Producer{
		sensorID: sensorID,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSHandshakeTimeout: tlsTimeout,
			},
			Timeout: httpTimeout,
		},
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
		if err := p.logHPFeeds(event); err != nil {
			return err
		}
	}
	if viper.GetBool("producers.http.enabled") {
		if err := p.logHTTP(event); err != nil {
			return err
		}
	}
	return nil
}

// logHPFeeds logs an event to a hpfeeds broker
func (p *Producer) logHPFeeds(event *Event) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(event); err != nil {
		return err
	}
	p.hpfChannel <- buf.Bytes()
	return nil
}

// logHTTP send logs to HTTP endpoint
func (p *Producer) logHTTP(event *Event) error {
	url, err := url.Parse(viper.GetString("producers.http.remote"))
	if err != nil {
		return err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", url.Scheme+"://"+url.Host+url.Path, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.URL.RawQuery = url.RawQuery
	if password, ok := url.User.Password(); ok {
		req.SetBasicAuth(url.User.Username(), password)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
