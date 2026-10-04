package producer

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/mushorg/glutton/connection"

	"github.com/d1str0/hpfeeds"
	"github.com/spf13/viper"
)

const (
	httpTimeout = 10 * time.Second
	tlsTimeout  = 5 * time.Second
)

// Producer for the producer
type Producer struct {
	sensorID      string
	sensorVersion string
	httpClient    *http.Client
	hpfClient     hpfeeds.Client
	hpfChannel    chan []byte
}

// Event is a struct for glutton events
type Event struct {
	Timestamp     time.Time   `json:"timestamp,omitempty"`
	StartedAt     time.Time   `json:"startedAt,omitempty"`
	DurationMs    int64       `json:"durationMs,omitempty"`
	Transport     string      `json:"transport,omitempty"`
	SrcHost       string      `json:"srcHost,omitempty"`
	SrcPort       string      `json:"srcPort,omitempty"`
	SrcPtr        string      `json:"srcPtr,omitempty"`
	DstHost       string      `json:"dstHost,omitempty"`
	DstPort       uint16      `json:"dstPort,omitempty"`
	SensorID      string      `json:"sensorID,omitempty"`
	SensorVersion string      `json:"sensorVersion,omitempty"`
	Rule          string      `json:"rule,omitempty"`
	RuleName      string      `json:"ruleName,omitempty"`
	Handler       string      `json:"handler,omitempty"`
	Payload       string      `json:"payload,omitempty"`
	PayloadHash   string      `json:"payloadHash,omitempty"`
	FrameCount    int         `json:"frameCount,omitempty"`
	EndReason     string      `json:"endReason,omitempty"`
	Scanner       string      `json:"scanner,omitempty"`
	Decoded       interface{} `json:"decoded,omitempty"`
}

// New initializes the producers
func New(sensorID, sensorVersion string) (*Producer, error) {
	producer := &Producer{
		sensorID:      sensorID,
		sensorVersion: sensorVersion,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSHandshakeTimeout: tlsTimeout,
			},
			Timeout: httpTimeout,
		},
	}
	if viper.GetBool("producers.hpfeeds.enabled") {
		producer.hpfClient = hpfeeds.NewClient(
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

// LogTCP is a meta caller for all producers
func (p *Producer) LogTCP(handler string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{}) error {
	event, err := p.makeEventTCP(handler, conn, md, payload, decoded)
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

// LogUDP is a meta caller for all producers
func (p *Producer) LogUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error {
	event, err := p.makeEventUDP(handler, srcAddr, dstAddr, md, payload, decoded)
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

// Check if a ip is private.
func isPrivateIP(ip string) bool {
	ipAddress := net.ParseIP(ip)
	return ipAddress.IsPrivate()
}

// logHTTP send logs to HTTP endpoint
func (p *Producer) logHTTP(event *Event) error {
	if isPrivateIP(event.SrcHost) {
		return nil
	}
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
