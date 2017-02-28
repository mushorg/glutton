package glutton

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	// "strings"

	log "github.com/Sirupsen/logrus"
	"github.com/kung-foo/freki"
	"github.com/mushorg/glutton/producer"
	uuid "github.com/satori/go.uuid"
)

const (
	gluttonServer = 5000
	tcpProxy      = 6000
)

// Glutton struct
type Glutton struct {
	logger           *log.Logger
	id               uuid.UUID
	processor        *freki.Processor
	rules            []*freki.Rule
	address          *producer.Address
	protocolHandlers map[string]protocolHandlerFunc
}

type protocolHandlerFunc func(conn net.Conn)

func (g *Glutton) makeID() error {
	dirName := "/var/lib/glutton"
	fileName := "glutton.id"
	filePath := filepath.Join(dirName, fileName)
	err := os.MkdirAll(dirName, 0644)
	if err != nil {
		return err
	}
	if f, err := os.OpenFile(filePath, os.O_RDWR, 0644); os.IsNotExist(err) {
		g.id = uuid.NewV4()
		errWrite := ioutil.WriteFile(filePath, g.id.Bytes(), 0644)
		if err != nil {
			return errWrite
		}
	} else {
		if err != nil {
			return err
		}
		buff, err := ioutil.ReadAll(f)
		if err != nil {
			return err
		}
		g.id, err = uuid.FromBytes(buff)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *Glutton) addServers() {
	// Adding a proxy server
	g.processor.AddServer(freki.NewTCPProxy(tcpProxy))
	// Adding Glutton Server
	g.processor.AddServer(freki.NewUserConnServer(gluttonServer))
}

// New creates a new Glutton instance
func New(processor *freki.Processor, log *log.Logger, rule []*freki.Rule, logHTTP *string) (g *Glutton, err error) {

	g.makeID()
	g.addServers()
	g.mapProtocolHandler()

	g = &Glutton{
		processor:        processor,
		logger:           log,
		rules:            rule,
		protocolHandlers: make(map[string]protocolHandlerFunc, 0),
		address:          producer.NewAddress(log, logHTTP),
	}

	return
}

// Start this is the main listener for rewritten package
func (g *Glutton) Start() {
	g.registerHandlers()
}

// registerConnections register protocol handlers to GluttonServer
func (g *Glutton) registerHandlers() {
	for _, rule := range g.rules {
		if rule.Type == "conn_handler" && rule.Target != "" {
			protocol := rule.Target
			g.processor.RegisterConnHandler(protocol, func(conn net.Conn, md *freki.Metadata) error {

				host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
				if md == nil {
					g.logger.Debugf("[glutton ] connection not tracked: %s:%s", host, port)
					return nil
				}
				g.logger.Debugf("[glutton ] new connection: %s:%s -> %d", host, port, uint(md.TargetPort))

				err := g.address.LogHTTP(host, port, md.TargetPort.String(), g.id.String(), md.Rule.String())
				if err != nil {
					g.logger.Error(err)
				}

				protocolHandler := g.protocolHandlers[protocol]
				go protocolHandler(conn)
				return nil
			})
		}
	}
}

func (g *Glutton) OnErrorExit(err error) {
	if err != nil {
		g.logger.Fatalf("[glutton ] %+v", err)
	}
}

func (g *Glutton) OnErrorClose(err error, conn net.Conn) {
	if err != nil {
		g.logger.Error(err)
		err = conn.Close()
		if err != nil {
			g.logger.Error(err)
		}
	}
}
