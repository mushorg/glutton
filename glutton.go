package glutton

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols"
	"github.com/mushorg/glutton/rules"
	"github.com/mushorg/glutton/scanner"

	"github.com/google/uuid"
	"github.com/seud0nym/tproxy-go/tproxy"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

// Glutton struct
type Glutton struct {
	id               uuid.UUID
	Logger           *zap.Logger
	Server           *Server
	rules            rules.Rules
	Producer         *producer.Producer
	conntable        *connection.ConnTable
	protocolHandlers map[string]protocols.HandlerFunc
	telnetProxy      *telnetProxy
	sshProxy         *sshProxy
	ctx              context.Context
	cancel           context.CancelFunc
	publicAddrs      []net.IP
	connHandlers     map[string]connHandlerFunc
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
func New(ctx context.Context) (*Glutton, error) {
	g := &Glutton{}
	g.ctx, g.cancel = context.WithCancel(ctx)

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

	g.conntable = connection.New()
	g.connHandlers = map[string]connHandlerFunc{}

	g.rules, err = rules.ParseRuleSpec(rulesFile)
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
func (g *Glutton) Init() error {
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

	// Start the Glutton server
	tcpServerPort := uint(viper.GetInt("ports.tcp"))
	udpServerPort := uint(viper.GetInt("ports.udp"))
	g.Server = NewServer(tcpServerPort, udpServerPort)
	if err := g.Server.Start(); err != nil {
		return err
	}

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

func (g *Glutton) udpListen() {
	buffer := make([]byte, 1024)
	for {
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(g.Server.udpListener, buffer)
		if err != nil {
			g.Logger.Error("failed to read UDP packet", zap.Error(err))
		}
		g.Logger.Info(fmt.Sprintf("UDP payload:\n%s", hex.Dump(buffer[:n%1024])))
		println(srcAddr.String(), dstAddr.String())
		if err := g.ProduceUDP("udp", srcAddr, dstAddr, nil, buffer[:n%1024], nil); err != nil {
			g.Logger.Error("failed to produce UDP payload", zap.Error(err))
		}
	}
}

// Start the listener, this blocks for new connections
func (g *Glutton) Start() error {
	quit := make(chan struct{}) // stop monitor on shutdown
	defer func() {
		quit <- struct{}{}
		g.Shutdown()
	}()

	g.startMonitor(quit)

	if err := setTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "tcp", uint32(g.Server.tcpPort)); err != nil {
		return err
	}

	if err := setTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "udp", uint32(g.Server.udpPort)); err != nil {
		return err
	}

	go g.udpListen()

	for {
		conn, err := g.Server.tcpListener.Accept()
		if err != nil {
			return err
		}

		rule, err := g.applyRules(conn)
		if err != nil {
			return fmt.Errorf("failed to apply rules: %w", err)
		}
		if rule == nil {
			rule = &rules.Rule{Target: "default"}
		}

		if err := g.conntable.RegisterConn(conn, rule); err != nil {
			return err
		}

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
		g.id = uuid.New()
		data, err := g.id.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal UUID: %w", err)
		}
		if err := os.WriteFile(filePath, data, 0744); err != nil {
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

type connHandlerFunc func(conn net.Conn, md *connection.Metadata) error

func (g *Glutton) registerConnHandler(target string, handler connHandlerFunc) error {
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

			g.registerConnHandler(handler, func(conn net.Conn, md *connection.Metadata) error {
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
	return g.conntable.Get(ckey)
}

// MetadataByConnection returns connection metadata by connection
func (g *Glutton) MetadataByConnection(conn net.Conn) (*connection.Metadata, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("faild to split remote address: %w", err)
	}
	ckey, err := connection.NewConnKeyByString(host, port)
	if err != nil {
		return nil, err
	}
	md := g.ConnectionByFlow(ckey)
	if md == nil {
		return nil, errors.New("not found")
	}
	return md, nil
}

func (g *Glutton) sanitizePayload(payload []byte) []byte {
	for _, ip := range g.publicAddrs {
		payload = []byte(strings.ReplaceAll(string(payload), ip.String(), "1.2.3.4"))
	}
	return payload
}

func (g *Glutton) Produce(handler string, conn net.Conn, md *connection.Metadata, payload []byte, decoded interface{}) error {
	if g.Producer != nil {
		payload = g.sanitizePayload(payload)
		return g.Producer.LogTCP(handler, conn, md, payload, decoded)
	}
	return nil
}

func (g *Glutton) ProduceUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md *connection.Metadata, payload []byte, decoded interface{}) error {
	if g.Producer != nil {
		payload = g.sanitizePayload(payload)
		return g.Producer.LogUDP("udp", srcAddr, dstAddr, md, payload, decoded)
	}
	return nil
}

// Shutdown the packet processor
func (g *Glutton) Shutdown() error {
	defer g.Logger.Sync()
	g.cancel() // close all connection

	if err := flushTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "tcp", uint32(g.Server.tcpPort)); err != nil {
		return err
	}
	if err := flushTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "udp", uint32(g.Server.udpPort)); err != nil {
		return err
	}

	g.Logger.Info("Shutting down processor")
	return g.Server.Shutdown()
}

func (g *Glutton) applyRules(conn net.Conn) (*rules.Rule, error) {
	match, err := g.rules.Match(conn)
	if err != nil {
		return nil, err
	}
	if match != nil {
		return match, err
	}
	return nil, nil
}
