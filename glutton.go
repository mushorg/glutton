package glutton

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"log/slog"
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

	"github.com/google/uuid"
	"github.com/seud0nym/tproxy-go/tproxy"
	"github.com/spf13/viper"
)

// Glutton struct
type Glutton struct {
	id                  uuid.UUID
	Logger              *slog.Logger
	Server              *Server
	rules               rules.Rules
	Producer            *producer.Producer
	connTable           *connection.ConnTable
	tcpProtocolHandlers map[string]protocols.TCPHandlerFunc
	udpProtocolHandlers map[string]protocols.UDPHandlerFunc
	ctx                 context.Context
	cancel              context.CancelFunc
	publicAddrs         []net.IP
}

//go:embed config/rules.yaml
var defaultRules []byte

func (g *Glutton) initConfig() error {
	viper.SetConfigName("config")
	viper.AddConfigPath(viper.GetString("confpath"))
	if _, err := os.Stat(viper.GetString("confpath")); !os.IsNotExist(err) {
		if err := viper.ReadInConfig(); err != nil {
			return err
		}
	}
	// If no config is found, use the defaults
	viper.SetDefault("ports.tcp", 5000)
	viper.SetDefault("ports.udp", 5001)
	viper.SetDefault("ports.ssh", 22)
	viper.SetDefault("max_tcp_payload", 4096)
	viper.SetDefault("conn_timeout", 45)
	viper.SetDefault("rules_path", "rules/rules.yaml")
	g.Logger.Debug("configuration set successfully", slog.String("reporter", "glutton"))
	return nil
}

// New creates a new Glutton instance
func New(ctx context.Context) (*Glutton, error) {
	g := &Glutton{
		tcpProtocolHandlers: make(map[string]protocols.TCPHandlerFunc),
		udpProtocolHandlers: make(map[string]protocols.UDPHandlerFunc),
		connTable:           connection.New(),
	}
	g.ctx, g.cancel = context.WithCancel(ctx)

	if err := g.makeID(); err != nil {
		return nil, err
	}
	g.Logger = producer.NewLogger(g.id.String())

	// Loading the configuration
	g.Logger.Info("Loading configurations from: config/config.yaml", slog.String("reporter", "glutton"))
	if err := g.initConfig(); err != nil {
		return nil, err
	}

	var rulesFile io.ReadCloser

	rulesPath := viper.GetString("rules_path")
	if _, err := os.Stat(rulesPath); !os.IsNotExist(err) {
		rulesFile, err = os.Open(rulesPath)
		if err != nil {
			return nil, err
		}
		defer rulesFile.Close()
	} else {
		g.Logger.Warn("No rules file found, using default rules", slog.String("reporter", "glutton"))
		rulesFile = io.NopCloser(bytes.NewBuffer(defaultRules))
	}

	var err error
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
	g.tcpProtocolHandlers = protocols.MapTCPProtocolHandlers(g.Logger, g)
	g.udpProtocolHandlers = protocols.MapUDPProtocolHandlers(g.Logger, g)

	return nil
}

func (g *Glutton) udpListen() {
	buffer := make([]byte, 1024)
	for {
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(g.Server.udpListener, buffer)
		if err != nil {
			g.Logger.Error("failed to read UDP packet", producer.ErrAttr(err))
		}

		rule, err := g.applyRules("udp", srcAddr, dstAddr)
		if err != nil {
			g.Logger.Error("failed to apply rules", producer.ErrAttr(err))
		}
		if rule == nil {
			rule = &rules.Rule{Target: "udp"}
		}
		md, err := g.connTable.Register(srcAddr.IP.String(), strconv.Itoa(int(srcAddr.AddrPort().Port())), dstAddr.AddrPort().Port(), rule)
		if err != nil {
			g.Logger.Error("failed to register UDP packet", producer.ErrAttr(err))
		}

		if hfunc, ok := g.udpProtocolHandlers[rule.Target]; ok {
			data := buffer[:n]
			go func() {
				if err := hfunc(g.ctx, srcAddr, dstAddr, data, md); err != nil {
					g.Logger.Error("failed to handle UDP payload", producer.ErrAttr(err))
				}
			}()
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

	if err := setTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "tcp", uint32(g.Server.tcpPort), uint32(viper.GetInt("ports.ssh"))); err != nil {
		return err
	}

	if err := setTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "udp", uint32(g.Server.udpPort), uint32(viper.GetInt("ports.ssh"))); err != nil {
		return err
	}

	go g.udpListen()

	for {
		select {
		case <-g.ctx.Done():
			return nil
		default:
		}
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

		md, err := g.connTable.RegisterConn(conn, rule)
		if err != nil {
			return err
		}

		g.Logger.Debug("new connection", slog.String("addr", conn.LocalAddr().String()), slog.String("handler", rule.Target))

		g.ctx = context.WithValue(g.ctx, ctxTimeout("timeout"), int64(viper.GetInt("conn_timeout")))
		if err := g.UpdateConnectionTimeout(g.ctx, conn); err != nil {
			g.Logger.Error("failed to set connection timeout", producer.ErrAttr(err))
		}

		if hfunc, ok := g.tcpProtocolHandlers[rule.Target]; ok {
			go func() {
				if err := hfunc(g.ctx, conn, md); err != nil {
					g.Logger.Error("failed to handle TCP connection", producer.ErrAttr(err), slog.String("handler", rule.Target))
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

type ctxTimeout string

// UpdateConnectionTimeout increase connection timeout limit on connection I/O operation
func (g *Glutton) UpdateConnectionTimeout(ctx context.Context, conn net.Conn) error {
	if timeout, ok := ctx.Value(ctxTimeout("timeout")).(int64); ok {
		if err := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
			return err
		}
	}
	return nil
}

// ConnectionByFlow returns connection metadata by connection key
func (g *Glutton) ConnectionByFlow(ckey [2]uint64) connection.Metadata {
	return g.connTable.Get(ckey)
}

// MetadataByConnection returns connection metadata by connection
func (g *Glutton) MetadataByConnection(conn net.Conn) (connection.Metadata, error) {
	host, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return connection.Metadata{}, fmt.Errorf("faild to split remote address: %w", err)
	}
	ckey, err := connection.NewConnKeyByString(host, port)
	if err != nil {
		return connection.Metadata{}, err
	}
	md := g.ConnectionByFlow(ckey)
	return md, nil
}

func (g *Glutton) sanitizePayload(payload []byte) []byte {
	for _, ip := range g.publicAddrs {
		payload = []byte(strings.ReplaceAll(string(payload), ip.String(), "1.2.3.4"))
	}
	return payload
}

func (g *Glutton) ProduceTCP(handler string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{}) error {
	if g.Producer != nil {
		payload = g.sanitizePayload(payload)
		return g.Producer.LogTCP(handler, conn, md, payload, decoded)
	}
	return nil
}

func (g *Glutton) ProduceUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error {
	if g.Producer != nil {
		payload = g.sanitizePayload(payload)
		return g.Producer.LogUDP("udp", srcAddr, dstAddr, md, payload, decoded)
	}
	return nil
}

// Shutdown the packet processor
func (g *Glutton) Shutdown() {
	g.cancel() // close all connection

	g.Logger.Info("Shutting down listeners")
	if err := g.Server.Shutdown(); err != nil {
		g.Logger.Error("failed to shutdown server", producer.ErrAttr(err))
	}

	g.Logger.Info("FLushing TCP iptables")
	if err := flushTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "tcp", uint32(g.Server.tcpPort), uint32(viper.GetInt("ports.ssh"))); err != nil {
		g.Logger.Error("failed to drop tcp iptables", producer.ErrAttr(err))
	}
	g.Logger.Info("FLushing UDP iptables")
	if err := flushTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "udp", uint32(g.Server.udpPort), uint32(viper.GetInt("ports.ssh"))); err != nil {
		g.Logger.Error("failed to drop udp iptables", producer.ErrAttr(err))
	}

	g.Logger.Info("All done")
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

func (g *Glutton) applyRulesOnConn(conn net.Conn) (*rules.Rule, error) {
	return g.applyRules("tcp", conn.RemoteAddr(), conn.LocalAddr())
}
