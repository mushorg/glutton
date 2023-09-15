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
	g.Logger = producer.NewLogger(g.id.String())

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

		rule, err := g.applyRules("udp", srcAddr, dstAddr)
		if err != nil {
			g.Logger.Error("failed to apply rules", zap.Error(err))
		}
		md, err := g.conntable.Register(srcAddr.IP.String(), strconv.Itoa(int(srcAddr.AddrPort().Port())), dstAddr.AddrPort().Port(), rule)
		if err != nil {
			g.Logger.Error("failed to register UDP packet", zap.Error(err))
		}
		g.Logger.Info(fmt.Sprintf("UDP payload:\n%s", hex.Dump(buffer[:n%1024])))
		if err := g.ProduceUDP("udp", srcAddr, dstAddr, md, buffer[:n%1024], nil); err != nil {
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

		rule, err := g.applyRulesOnConn(conn)
		if err != nil {
			return fmt.Errorf("failed to apply rules: %w", err)
		}
		if rule == nil {
			rule = &rules.Rule{Target: "default"}
		}

		if _, err := g.conntable.RegisterConn(conn, rule); err != nil {
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

// closeOnShutdown close all connections before system shutdown
func (g *Glutton) closeOnShutdown(conn net.Conn, done <-chan struct{}) {
	select {
	case <-g.ctx.Done():
		if err := conn.Close(); err != nil {
			g.Logger.Error("error on ctx close", zap.Error(err))
		}
		return
	case <-done:
		if err := conn.Close(); err != nil {
			g.Logger.Debug("error on handler close", zap.Error(err))
		}
		return
	}
}

type contextKey string

// Drive child context from parent context with additional value required for sepcific handler
func (g *Glutton) contextWithTimeout(timeInSeconds int) context.Context {
	return context.WithValue(g.ctx, contextKey("timeout"), time.Duration(timeInSeconds)*time.Second)
}

// UpdateConnectionTimeout increase connection timeout limit on connection I/O operation
func (g *Glutton) UpdateConnectionTimeout(ctx context.Context, conn net.Conn) {
	if timeout, ok := ctx.Value("timeout").(time.Duration); ok {
		conn.SetDeadline(time.Now().Add(timeout))
	}
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

			if g.protocolHandlers[rule.Target] == nil {
				g.Logger.Warn(fmt.Sprintf("no handler found for '%s' protocol", rule.Target))
				continue
			}

			g.registerConnHandler(rule.Target, func(conn net.Conn, md *connection.Metadata) error {
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
					zap.String("handler", rule.Target),
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
				err = g.protocolHandlers[rule.Target](ctx, conn)
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

func (g *Glutton) applyRulesOnConn(conn net.Conn) (*rules.Rule, error) {
	match, err := g.rules.Match("tcp", conn.RemoteAddr(), conn.LocalAddr())
	if err != nil {
		return nil, err
	}
	if match != nil {
		return match, err
	}
	return nil, nil
}

func (g *Glutton) applyRules(network string, srcAddr, dstAddr net.Addr) (*rules.Rule, error) {
	match, err := g.rules.Match(network, srcAddr, dstAddr)
	if err != nil {
		return nil, err
	}
	if match != nil {
		return match, err
	}
	return nil, nil
}
