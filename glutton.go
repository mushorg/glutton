package glutton

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kung-foo/freki"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols"
	"github.com/mushorg/glutton/scanner"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Glutton struct
type Glutton struct {
	id               uuid.UUID
	Logger           *zap.Logger
	Processor        *freki.Processor
	rules            []*freki.Rule
	Producer         *producer.Producer
	protocolHandlers map[string]protocols.HandlerFunc
	telnetProxy      *telnetProxy
	sshProxy         *sshProxy
	ctx              context.Context
	cancel           context.CancelFunc
	publicAddrs      []net.IP
}

func (g *Glutton) initConfig() error {
	viper.SetConfigName("config")
	viper.AddConfigPath(viper.GetString("confpath"))
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	// If no config is found, use the defaults
	viper.SetDefault("glutton_server", 5000)
	viper.SetDefault("max_tcp_payload", 4096)
	viper.SetDefault("rules_path", "rules/rules.yaml")
	g.Logger.Debug("configuration loaded successfully", zap.String("reporter", "glutton"))
	return nil
}

// New creates a new Glutton instance
func New() (*Glutton, error) {
	g := &Glutton{}
	g.protocolHandlers = make(map[string]protocols.HandlerFunc)
	if err := g.makeID(); err != nil {
		return nil, err
	}
	g.Logger = NewLogger(g.id.String())

	// Loading the configuration
	g.Logger.Info("Loading configurations from: config/config.yaml", zap.String("reporter", "glutton"))
	if err := g.initConfig(); err != nil {
		return nil, err
	}

	rulesPath := viper.GetString("rules_path")
	rulesFile, err := os.Open(rulesPath)
	if err != nil {
		return nil, err
	}
	defer rulesFile.Close()

	g.rules, err = freki.ReadRulesFromFile(rulesFile)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// Init initializes freki and handles
func (g *Glutton) Init() error {
	ctx := context.Background()
	g.ctx, g.cancel = context.WithCancel(ctx)

	gluttonServerPort := uint(viper.GetInt("glutton_server"))

	// Initiate the freki processor
	var err error
	g.Processor, err = freki.New(viper.GetString("interface"), g.rules, DummyLogger{})
	if err != nil {
		return err
	}

	g.publicAddrs, err = getNonLoopbackIPs(viper.GetString("interface"))
	if err != nil {
		return err
	}

	for _, sIP := range viper.GetStringSlice("addresses") {
		if ip := net.ParseIP(sIP); ip != nil {
			g.publicAddrs = append(g.publicAddrs, ip)
		}
	}

	// Initiating glutton server
	g.Processor.AddServer(freki.NewUserConnServer(gluttonServerPort))
	// Initiating log producers
	if viper.GetBool("producers.enabled") {
		g.Producer, err = producer.New(g.id.String())
		if err != nil {
			return err
		}
	}
	// Initiating protocol handlers
	g.protocolHandlers = protocols.MapProtocolHandlers(g.Logger, g)
	g.protocolHandlers["proxy_tcp"] = func(ctx context.Context, conn net.Conn) error {
		return g.tcpProxy(ctx, conn)
	}
	g.protocolHandlers["proxy_ssh"] = func(ctx context.Context, conn net.Conn) error {
		return g.sshProxy.handle(ctx, conn)
	}
	g.protocolHandlers["proxy_telnet"] = func(ctx context.Context, conn net.Conn) error {
		return g.telnetProxy.handle(ctx, conn)
	}
	g.registerHandlers()

	return g.Processor.Init()
}

// Start the packet processor
func (g *Glutton) Start() error {
	quit := make(chan struct{}) // stop monitor on shutdown
	defer func() {
		quit <- struct{}{}
		g.Shutdown()
	}()

	g.startMonitor(quit)
	return g.Processor.Start()
}

func (g *Glutton) makeID() error {
	fileName := "glutton.id"
	filePath := filepath.Join(viper.GetString("var-dir"), fileName)
	if err := os.MkdirAll(viper.GetString("var-dir"), 0744); err != nil {
		return fmt.Errorf("failed to create var-dir: %w", err)
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		g.id = uuid.NewV4()
		if err := ioutil.WriteFile(filePath, g.id.Bytes(), 0744); err != nil {
			return fmt.Errorf("failed to create new PID file: %w", err)
		}
	} else {
		if err != nil {
			return fmt.Errorf("failed to access PID file: %w", err)
		}
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open PID file: %w", err)
		}
		buff, err := ioutil.ReadAll(f)
		if err != nil {
			return fmt.Errorf("failed to read PID file: %w", err)
		}
		g.id, err = uuid.FromBytes(buff)
		if err != nil {
			return fmt.Errorf("failed to create UUID from PID filed content: %w", err)
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
			case "proxy_ssh":
				handler = rule.Name
				if err := g.NewSSHProxy(rule.Target); err != nil {
					g.Logger.Error("failed to initialize SSH proxy", zap.Error(err))
					continue
				}
				rule.Target = handler
			case "proxy_telnet":
				handler = rule.Name
				if err := g.NewTelnetProxy(rule.Target); err != nil {
					g.Logger.Error("failed to initialize TELNET proxy", zap.Error(err))
					continue
				}
				rule.Target = handler
			default:
				handler = rule.Target
			}

			if g.protocolHandlers[handler] == nil {
				g.Logger.Warn(fmt.Sprintf("no handler found for '%s' protocol", handler))
				continue
			}

			g.Processor.RegisterConnHandler(handler, func(conn net.Conn, md *freki.Metadata) error {
				host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
				if err != nil {
					return fmt.Errorf("failed to split remote address: %w", err)
				}

				if md == nil {
					g.Logger.Debug(fmt.Sprintf("connection not tracked: %s:%s", host, port))
					return nil
				}
				g.Logger.Debug(
					fmt.Sprintf("new connection: %s:%s -> %d", host, port, md.TargetPort),
					zap.String("host", host),
					zap.String("src_port", port),
					zap.String("dest_port", strconv.Itoa(int(md.TargetPort))),
					zap.String("handler", handler),
				)

				if g.Producer != nil {
					if err := g.Producer.Log(conn, md, nil); err != nil {
						return fmt.Errorf("producer log error: %w", err)
					}
				}

				matched, name, err := scanner.IsScanner(net.ParseIP(host))
				if err != nil {
					return err
				}
				if matched {
					g.Logger.Info("IP from a known scanner", zap.String("host", host), zap.String("scanner", name), zap.String("dest_port", strconv.Itoa(int(md.TargetPort))))
					return nil
				}

				done := make(chan struct{})
				go g.closeOnShutdown(conn, done)
				if err = conn.SetDeadline(time.Now().Add(time.Duration(viper.GetInt("conn_timeout")) * time.Second)); err != nil {
					return fmt.Errorf("failed to set connection deadline: %w", err)
				}
				ctx := g.contextWithTimeout(72)
				err = g.protocolHandlers[handler](ctx, conn)
				done <- struct{}{}
				if err != nil {
					return fmt.Errorf("protocol handler error: %w", err)
				}
				return nil
			})
		}
	}
}

// ConnectionByFlow returns connection metadata by connection key
func (g *Glutton) ConnectionByFlow(ckey [2]uint64) *freki.Metadata {
	return g.Processor.Connections.GetByFlow(ckey)
}

// MetadataByConnection returns connection metadata by connection
func (g *Glutton) MetadataByConnection(conn net.Conn) (*freki.Metadata, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("faild to split remote address: %w", err)
	}
	ckey := freki.NewConnKeyByString(host, port)
	return g.Processor.Connections.GetByFlow(ckey), nil
}

func (g *Glutton) sanitizePayload(payload []byte) []byte {
	for _, ip := range g.publicAddrs {
		payload = []byte(strings.ReplaceAll(string(payload), ip.String(), "1.2.3.4"))
	}
	return payload
}

func (g *Glutton) Produce(conn net.Conn, md *freki.Metadata, payload []byte) error {
	if g.Producer != nil {
		payload = g.sanitizePayload(payload)
		return g.Producer.Log(conn, md, payload)
	}
	return nil
}

// Shutdown the packet processor
func (g *Glutton) Shutdown() error {
	defer g.Logger.Sync()
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
	g.Logger.Info("Shutting down processor")
	return g.Processor.Shutdown()
}
