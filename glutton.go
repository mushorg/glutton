package glutton

import (
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

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
	logger           freki.Logger
	processor        *freki.Processor
	rules            []*freki.Rule
	producer         *producer.Config
	protocolHandlers map[string]protocolHandlerFunc
	sshProxy         *sshProxy
}

type protocolHandlerFunc func(conn net.Conn)

// New creates a new Glutton instance
func New(iface string, conf *viper.Viper, logger freki.Logger) (*Glutton, error) {
	rulesPath := conf.GetString("rules_path")
	rulesFile, err := os.Open(rulesPath)
	if err != nil {
		// TODO formate error
		return nil, err
	}

	rules, err := freki.ReadRulesFromFile(rulesFile)
	if err != nil {
		return nil, err
	}

	// Initiate the freki processor
	processor, err := freki.New(iface, rules, logger)
	if err != nil {
		return nil, err
	}

	glutton := &Glutton{
		conf:             conf,
		logger:           logger,
		processor:        processor,
		rules:            rules,
		protocolHandlers: make(map[string]protocolHandlerFunc, 0),
	}

	return glutton, nil

}

// Init initializes freki and handles
func (g *Glutton) Init() (err error) {
	tcpProxyPort := uint(g.conf.GetInt("proxy_tcp"))
	gluttonServerPort := uint(g.conf.GetInt("glutton_server"))

	// Initiating tcp proxy server
	g.processor.AddServer(freki.NewTCPProxy(tcpProxyPort))
	// Initiating glutton server
	g.processor.AddServer(freki.NewUserConnServer(gluttonServerPort))

	g.makeID()
	g.producer = producer.Init(g.id.String(), g.logger, g.conf.GetString("gollum"))

	// TODO: in Freki updated version
	// g.processor.GetPublicAddresses()

	g.startMonitor()

	g.mapProtocolHandlers()
	g.registerHandlers()
	err = g.processor.Init()
	if err != nil {
		return
	}

	return nil
}

// Start the packet processor
func (g *Glutton) Start() (err error) {
	defer g.Shutdown()
	err = g.processor.Start()
	return
}

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

// registerHandlers register protocol handlers to glutton_server
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
					g.logger.Error(errors.Wrap(formatErrorMsg("Failed to initialize SSH Proxy: ", err), "ssh.prxy"))
					continue
				}
			}
			g.processor.RegisterConnHandler(protocol, func(conn net.Conn, md *freki.Metadata) error {
				defer func() {
					if conn != nil {
						conn.Close()
					}
				}()

				host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
				if err != nil {
					return err
				}

				if md == nil {
					g.logger.Debugf("[glutton ] connection not tracked: %s:%s", host, port)
					return nil
				}
				g.logger.Debugf("[glutton ] new connection: %s:%s -> %d", host, port, uint(md.TargetPort))

				err = g.producer.LogHTTP(conn, md, nil, "")
				if err != nil {
					g.logger.Errorf("[glutton ] %v", err)
				}

				// TODO: modify handlers to return an error
				g.protocolHandlers[protocol](conn)
				return nil
			})
		}
	}
}

// Shutdown the packet processor
func (g *Glutton) Shutdown() (err error) {
	return g.processor.Shutdown()
}

// OnErrorClose prints the error, closes the connection and exits
func (g *Glutton) onErrorClose(err error, conn net.Conn) {
	if err != nil {
		g.logger.Error(err)
		err = conn.Close()
		if err != nil {
			g.logger.Error(err)
		}
	}
}
