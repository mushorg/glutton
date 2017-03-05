package glutton

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	log "github.com/Sirupsen/logrus"
	"github.com/kung-foo/freki"
	"github.com/mushorg/glutton/producer"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
)

// Glutton struct
type Glutton struct {
	id               uuid.UUID
	conf             *viper.Viper
	logger           *log.Logger
	processor        *freki.Processor
	rules            []*freki.Rule
	producer         *producer.Config
	protocolHandlers map[string]protocolHandlerFunc
	sshProxy         *SSHProxy
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
	p1 := uint(g.conf.GetInt("proxy_tcp"))
	p2 := uint(g.conf.GetInt("glutton_server"))

	// Adding a proxy server
	g.processor.AddServer(freki.NewTCPProxy(p1))
	// Adding Glutton Server
	g.processor.AddServer(freki.NewUserConnServer(p2))
}

// New creates a new Glutton instance
func New(processor *freki.Processor, log *log.Logger, rule []*freki.Rule, conf *viper.Viper) (g *Glutton, err error) {

	g = &Glutton{
		conf:             conf,
		logger:           log,
		processor:        processor,
		rules:            rule,
		protocolHandlers: make(map[string]protocolHandlerFunc, 0),
	}

	g.makeID()
	g.producer = producer.Init(g.id.String(), log, conf.GetString("gollum"))
	g.addServers()
	g.mapProtocolHandler()
	return
}

// Start this is the main listener for rewritten package
func (g *Glutton) Start() {
	g.registerHandlers()
}

// registerConnections register protocol handlers to glutton_server
func (g *Glutton) registerHandlers() {
	for _, rule := range g.rules {
		if rule.Type == "conn_handler" && rule.Target != "" {
			protocol := rule.Target
			if g.protocolHandlers[protocol] == nil {
				g.logger.Errorf("[glutton ] No handler found for %v Protocol", protocol)
				continue
			}
			if protocol == "proxy_ssh" {
				err := g.NewSSHProxy()
				if err != nil {
					g.logger.Error(errors.Wrap(interpreter("Failed to initialize SSH Proxy: ", err), "ssh.prxy"))
					continue
				}
			}
			g.processor.RegisterConnHandler(protocol, func(conn net.Conn, md *freki.Metadata) error {

				host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
				if md == nil {
					g.logger.Debugf("[glutton ] connection not tracked: %s:%s", host, port)
					return nil
				}
				g.logger.Debugf("[glutton ] new connection: %s:%s -> %d", host, port, uint(md.TargetPort))

				err := g.producer.LogHTTP(host, port, md.TargetPort.String(), md.Rule.String())
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
