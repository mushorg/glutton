package glutton

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols"
	"github.com/mushorg/glutton/rules"
	"github.com/mushorg/glutton/scanner"

	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Glutton struct
type Glutton struct {
	id               uuid.UUID
	Logger           *zap.Logger
	Server           *Server
	rules            []*rules.Rule
	Producer         *producer.Producer
	conntable        *connection.ConnTable
	protocolHandlers map[string]protocols.HandlerFunc
	telnetProxy      *telnetProxy
	sshProxy         *sshProxy
	ctx              context.Context
	cancel           context.CancelFunc
	publicAddrs      []net.IP
	connHandlers     map[string]ConnHandlerFunc
}

func (g *Glutton) initConfig() error {
	viper.SetConfigName("config")
	viper.AddConfigPath(viper.GetString("confpath"))
	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	// If no config is found, use the defaults
	viper.SetDefault("ports.glutton_server", 5000)
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

	g.conntable = connection.NewConnTable()
	g.connHandlers = map[string]ConnHandlerFunc{}

	g.rules, err = rules.ReadRulesFromFile(rulesFile)
	if err != nil {
		return nil, err
	}

	for idx, rule := range g.rules {
		if err := rules.InitRule(idx, rule); err != nil {
			return nil, fmt.Errorf("failed to initialize rule: %w", err)
		}
	}

	return g, nil
}

// Init initializes server and handles
func (g *Glutton) Init(ctx context.Context) error {
	g.ctx, g.cancel = context.WithCancel(ctx)

	var err error
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
	gluttonServerPort := uint(viper.GetInt("ports.glutton_server"))
	g.Server = InitServer(gluttonServerPort)

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

	return nil
}

func splitAddr(addr string) (net.IP, layers.TCPPort, error) {
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	sIP := net.ParseIP(ip)

	dPort, err := strconv.Atoi(port)
	if err != nil {
		return nil, 0, err
	}
	return sIP, layers.TCPPort(dPort), nil
}

func fakePacketBytes(conn net.Conn) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}

	sIP, sPort, err := splitAddr(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}
	dIP, dPort, err := splitAddr(conn.LocalAddr().String())
	if err != nil {
		return nil, err
	}

	if err := gopacket.SerializeLayers(buf, opts,
		&layers.IPv4{
			SrcIP: sIP,
			DstIP: dIP,
		},
		&layers.TCP{
			SrcPort: sPort,
			DstPort: dPort,
		},
		gopacket.Payload([]byte{})); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Start the listener, this blocks for new connections
func (g *Glutton) Start() error {
	quit := make(chan struct{}) // stop monitor on shutdown
	defer func() {
		quit <- struct{}{}
		g.Shutdown()
	}()

	g.startMonitor(quit)

	if err := setTProxyIPTables("", uint32(g.Server.port)); err != nil {
		return err
	}

	if err := g.Server.Start(g.ctx); err != nil {
		return err
	}

	for {
		conn, err := g.Server.ln.Accept()
		if err != nil {
			return err
		}
		println("remote", conn.RemoteAddr().String())
		data, err := fakePacketBytes(conn)
		if err != nil {
			return fmt.Errorf("failed to fake packet: %w", err)
		}

		rule, err := g.applyRules(data)
		if err != nil {
			return fmt.Errorf("failed to apply rules: %w", err)
		}
		if rule == nil {
			rule = &rules.Rule{Target: "default"}
		}
		println("rule", rule.Target)

		if hfunc, ok := g.protocolHandlers[rule.Target]; ok {
			go func() {
				if err := hfunc(g.ctx, conn); err != nil {
					fmt.Printf("failed to handle connection: %s\n", err)
				}
			}()
		}
	}
}

func (g *Glutton) makeID() error {
	filePath := filepath.Join(viper.GetString("var-dir"), "glutton.id")
	if err := os.MkdirAll(viper.GetString("var-dir"), 0744); err != nil {
		return fmt.Errorf("failed to create var-dir: %w", err)
	}
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		g.id = uuid.NewV4()
		if err := os.WriteFile(filePath, g.id.Bytes(), 0744); err != nil {
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
		buff, err := io.ReadAll(f)
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

type ConnHandlerFunc func(conn net.Conn, md *connection.Metadata) error

func (g *Glutton) RegisterConnHandler(target string, handler ConnHandlerFunc) error {
	if _, ok := g.connHandlers[target]; ok {
		return fmt.Errorf("conn handler already registered for %s", target)
	}
	g.connHandlers[target] = handler
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

			g.RegisterConnHandler(handler, func(conn net.Conn, md *connection.Metadata) error {
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
func (g *Glutton) ConnectionByFlow(ckey [2]uint64) *connection.Metadata {
	return g.conntable.GetByFlow(ckey)
}

// MetadataByConnection returns connection metadata by connection
func (g *Glutton) MetadataByConnection(conn net.Conn) (*connection.Metadata, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("faild to split remote address: %w", err)
	}
	ckey := connection.NewConnKeyByString(host, port)
	return g.ConnectionByFlow(ckey), nil
}

func (g *Glutton) sanitizePayload(payload []byte) []byte {
	for _, ip := range g.publicAddrs {
		payload = []byte(strings.ReplaceAll(string(payload), ip.String(), "1.2.3.4"))
	}
	return payload
}

func (g *Glutton) Produce(conn net.Conn, md *connection.Metadata, payload []byte) error {
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

	g.Logger.Info("Shutting down processor")
	return g.Server.Shutdown()
}

func (g *Glutton) applyRules(d []byte) (*rules.Rule, error) {
	for _, rule := range g.rules {
		match, err := rule.RunMatch(d)
		if err != nil {
			return nil, err
		}
		if match != nil {
			return match, err
		}
	}
	return nil, nil
}
