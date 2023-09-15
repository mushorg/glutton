package producer

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/scanner"

	"github.com/d1str0/hpfeeds"
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
	hpfClient  hpfeeds.Client
	hpfChannel chan []byte
}

// Event is a struct for glutton events
type Event struct {
	Timestamp time.Time   `json:"timestamp,omitempty"`
	Transport string      `json:"transport,omitempty"`
	SrcHost   string      `json:"srcHost,omitempty"`
	SrcPort   string      `json:"srcPort,omitempty"`
	DstPort   uint16      `json:"dstPort,omitempty"`
	SensorID  string      `json:"sensorID,omitempty"`
	Rule      string      `json:"rule,omitempty"`
	Handler   string      `json:"handler,omitempty"`
	Payload   string      `json:"payload,omitempty"`
	Scanner   string      `json:"scanner,omitempty"`
	Decoded   interface{} `json:"decoded,omitempty"`
}

func makeEventTCP(handler string, conn net.Conn, md *connection.Metadata, payload []byte, decoded interface{}, sensorID string) (*Event, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}

	_, scannerName, err := scanner.IsScanner(net.ParseIP(host))
	if err != nil {
		return nil, err
	}

	event := Event{
		Timestamp: time.Now().UTC(),
		Transport: "tcp",
		SrcHost:   host,
		SrcPort:   port,
		SensorID:  sensorID,
		Handler:   handler,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Scanner:   scannerName,
		Decoded:   decoded,
	}
	if md != nil {
		event.DstPort = uint16(md.TargetPort)
		if md.Rule != nil {
			event.Rule = md.Rule.String()
		}
	}
	return &event, nil
}

func makeEventUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md *connection.Metadata, payload []byte, decoded interface{}, sensorID string) (*Event, error) {
	_, scannerName, err := scanner.IsScanner(net.ParseIP(srcAddr.IP.String()))
	if err != nil {
		return nil, err
	}

	event := Event{
		Timestamp: time.Now().UTC(),
		Transport: "udp",
		SrcHost:   srcAddr.IP.String(),
		SrcPort:   strconv.Itoa(int(srcAddr.AddrPort().Port())),
		SensorID:  sensorID,
		Handler:   handler,
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Scanner:   scannerName,
		Decoded:   decoded,
	}
	if md != nil {
		event.DstPort = uint16(md.TargetPort)
		if md.Rule != nil {
			event.Rule = md.Rule.String()
		}
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
func (p *Producer) LogTCP(handler string, conn net.Conn, md *connection.Metadata, payload []byte, decoded interface{}) error {
	event, err := makeEventTCP(handler, conn, md, payload, decoded, p.sensorID)
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
func (p *Producer) LogUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md *connection.Metadata, payload []byte, decoded interface{}) error {
	event, err := makeEventUDP(handler, srcAddr, dstAddr, md, payload, decoded, p.sensorID)
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
