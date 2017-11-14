package glutton

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/kung-foo/freki"
	"github.com/mushorg/glutton/config"
	"github.com/mushorg/glutton/producer"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	log "go.uber.org/zap"
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
	sshProxy         *sshProxy
	ctx              context.Context
	cancel           context.CancelFunc
}

type protocolHandlerFunc func(ctx context.Context, conn net.Conn) error

// New creates a new Glutton instance
func New(args map[string]interface{}) (*Glutton, error) {
	var (
		iface    string = args["--interface"].(string)
		logPath         = args["--logpath"].(string)
		confPath        = args["--confpath"].(string)
		debug    string = args["--debug"].(string)
	)

	gtn := &Glutton{}
	err := gtn.makeID()
	if err != nil {
		return nil, err
	}
	if gtn.logger, err = initLogger(&logPath, gtn.id.String(), &debug); err != nil {
		return nil, err
	}

	// Loading the congiguration
	gtn.logger.Info("[glutton ] Loading configurations from: config/conf.yaml")
	gtn.conf = config.Init(&confPath, gtn.logger)

	rulesPath := gtn.conf.GetString("rules_path")
	rulesFile, err := os.Open(rulesPath)
	defer rulesFile.Close()
	if err != nil {
		return nil, err
	}

	gtn.rules, err = freki.ReadRulesFromFile(rulesFile)
	if err != nil {
		return nil, err
	}

	// Initiate the freki processor
	gtn.processor, err = freki.New(iface, gtn.rules, nil)
	if err != nil {
		return nil, err
	}

	return gtn, nil

}

// Init initializes freki and handles
func (g *Glutton) Init() (err error) {

	ctx := context.Background()
	g.ctx, g.cancel = context.WithCancel(ctx)

	g.protocolHandlers = make(map[string]protocolHandlerFunc, 0)

	gluttonServerPort := uint(g.conf.GetInt("glutton_server"))

	// Initiating glutton server
	g.processor.AddServer(freki.NewUserConnServer(gluttonServerPort))
	// Initiating log producer
	if g.conf.GetBool("enableGollum") {
		g.producer = producer.Init(g.id.String(), g.conf.GetString("gollumAddress"))
	}
	// Initiating protocol handlers
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

	quit := make(chan struct{}) // stop monitor on shutdown
	defer func() {
		quit <- struct{}{}
		g.Shutdown()
	}()

	g.startMonitor(quit)
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

			var handler string

			switch rule.Name {

			case "proxy_tcp":
				handler = rule.Name
				g.protocolHandlers[rule.Target] = g.protocolHandlers[handler]
				delete(g.protocolHandlers, handler)
				handler = rule.Target
				break

			case "proxy_ssh":
				handler = rule.Name
				err := g.NewSSHProxy(rule.Target)
				if err != nil {
					g.logger.Error(fmt.Sprintf("[ssh.prxy] failed to initialize SSH proxy"))
					continue
				}
				rule.Target = handler
				break

			default:
				handler = rule.Target
				break
			}

			if g.protocolHandlers[handler] == nil {
				g.logger.Warn(fmt.Sprintf("[glutton ] no handler found for %v protocol", handler))
				continue
			}

			g.processor.RegisterConnHandler(handler, func(conn net.Conn, md *freki.Metadata) error {

				host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
				if err != nil {
					return err
				}

				if md == nil {
					g.logger.Debug(fmt.Sprintf("[glutton ] connection not tracked: %s:%s", host, port))
					return nil
				}
				g.logger.Debug(fmt.Sprintf("[glutton ] new connection: %s:%s -> %d", host, port, md.TargetPort))

				if g.producer != nil {
					err = g.producer.LogHTTP(conn, md, nil, "")
					if err != nil {
						g.logger.Error(fmt.Sprintf("[glutton ] error: %v", err))
					}
				}

				done := make(chan struct{})
				go g.closeOnShutdown(conn, done)
				conn.SetDeadline(time.Now().Add(45 * time.Second))
				ctx := g.contextWithTimeout(72)
				err = g.protocolHandlers[handler](ctx, conn)
				done <- struct{}{}
				return err
			})
		}
	}
}

// Shutdown the packet processor
func (g *Glutton) Shutdown() (err error) {
	defer g.logger.Sync()
	g.cancel() // close all connection

	/** TODO:
	 ** May be there exist a better way to wait for all connections to be closed but I am unable
	 ** to find. The only link we have between program and goroutines is context.
	 ** context.cancel() signal routines to abandon their work and does not wait
	 ** for the work to stop. And in any case if fails then there will be definitely a
	 ** goroutine leak. May be it is possible in future when we have connection counter so we can keep
	 ** that counter synchronized with number of goroutines (connections) with help of context and on
	 ** shutdown we wait until counter goes to zero.
	 */

	time.Sleep(2 * time.Second)
	return g.processor.Shutdown()
}

// OnErrorClose prints the error, closes the connection and exits
func (g *Glutton) onErrorClose(err error, conn net.Conn) {
	if err != nil {
		g.logger.Error(fmt.Sprintf("[glutton ] error: %v", err))
		err = conn.Close()
		if err != nil {
			g.logger.Error(fmt.Sprintf("[glutton ] error: %v", err))
		}
	}
}
