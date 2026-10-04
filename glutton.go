package glutton

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols"
	"github.com/mushorg/glutton/protocols/spicy"
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

//go:embed config/config.yaml
var defaultConfig []byte

func (g *Glutton) initConfig() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(viper.GetString("confpath"))
	if _, err := os.Stat(viper.GetString("confpath")); !os.IsNotExist(err) {
		g.Logger.Info("Using configuration file", slog.String("path", viper.GetString("confpath")), slog.String("reporter", "glutton"))
		return viper.ReadInConfig()
	}

	g.Logger.Info("No configuration file found, using default configuration", slog.String("reporter", "glutton"))
	return viper.ReadConfig(bytes.NewBuffer(defaultConfig))
}

// New creates a new Glutton instance
func New(ctx context.Context) (*Glutton, error) {
	g := &Glutton{
		tcpProtocolHandlers: make(map[string]protocols.TCPHandlerFunc),
		udpProtocolHandlers: make(map[string]protocols.UDPHandlerFunc),
	}
	g.ctx, g.cancel = context.WithCancel(ctx)

	g.connTable = connection.New(ctx)
	if err := g.makeID(); err != nil {
		return nil, err
	}
	g.Logger = producer.NewLogger(g.id.String())

	// Loading the configuration
	g.Logger.Info("Loading configurations", slog.String("reporter", "glutton"))
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
	g.rules, err = rules.Init(rulesFile)
	if err != nil {
		return nil, err
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
		g.Producer, err = producer.New(g.id.String(), viper.GetString("sensor_version"))
		if err != nil {
			return err
		}
	}
	// Initiating protocol handlers
	g.tcpProtocolHandlers = protocols.MapTCPProtocolHandlers(g.Logger, g)
	g.udpProtocolHandlers = protocols.MapUDPProtocolHandlers(g.Logger, g)

	// Initializing Spicy parsers
	if viper.GetBool("spicy.enabled") {
		if err := spicy.Initialize(g.Logger); err != nil {
			return fmt.Errorf("failed to initialize Spicy: %w", err)
		}
	}

	return nil
}

func (g *Glutton) udpListen(wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
	}()
	buffer := make([]byte, 65535)
	for {
		select {
		case <-g.ctx.Done():
			if err := g.Server.udpConn.Close(); err != nil {
				g.Logger.Error("Failed to close UDP listener", producer.ErrAttr(err))
			}
			return
		default:
		}
		g.Server.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, srcAddr, dstAddr, err := tproxy.ReadFromUDP(g.Server.udpConn, buffer)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}
			g.Logger.Error("Failed to read UDP packet", producer.ErrAttr(err))
			continue
		}

		rule, err := g.applyRules("udp", srcAddr, dstAddr)
		if err != nil {
			g.Logger.Error("Failed to apply rules", producer.ErrAttr(err))
		}
		if rule == nil {
			rule = &rules.Rule{Target: "udp"}
		}
		md, err := g.connTable.Register(srcAddr.IP.String(), strconv.Itoa(int(srcAddr.AddrPort().Port())), dstAddr.AddrPort().Port(), dstAddr.IP.String(), rule)
		if err != nil {
			g.Logger.Error("Failed to register UDP packet", producer.ErrAttr(err))
		}

		var handlerName string
		switch rule.Type {
		case "proxy_udp":
			handlerName = rule.Type
		default:
			handlerName = rule.Target
		}

		if hfunc, ok := g.udpProtocolHandlers[handlerName]; ok {
			data := append([]byte(nil), buffer[:n]...)
			go func() {
				if err := hfunc(g.ctx, srcAddr, dstAddr, data, md); err != nil {
					g.Logger.Error("Failed to handle UDP payload", producer.ErrAttr(err))
				}
			}()
		}
	}
}

func (g *Glutton) tcpListen() {
	for {
		select {
		case <-g.ctx.Done():
			if err := g.Server.tcpListener.Close(); err != nil {
				g.Logger.Error("Failed to close TCP listener", producer.ErrAttr(err))
			}
			return
		default:
		}

		conn, err := g.Server.tcpListener.Accept()
		if err != nil {
			g.Logger.Error("Failed to accept connection", producer.ErrAttr(err))
			continue
		}

		rule, err := g.applyRulesOnConn(conn)
		if err != nil {
			g.Logger.Error("Failed to apply rules", producer.ErrAttr(err))
			continue
		}
		if rule == nil {
			rule = &rules.Rule{Target: "default"}
		}

		md, err := g.connTable.RegisterConn(conn, rule)
		if err != nil {
			g.Logger.Error("Failed to register connection", producer.ErrAttr(err))
			continue
		}

		g.Logger.Debug("new connection", slog.String("addr", conn.LocalAddr().String()), slog.String("handler", rule.Target))

		g.ctx = context.WithValue(g.ctx, ctxTimeout("timeout"), int64(viper.GetInt("conn_timeout")))
		if err := g.UpdateConnectionTimeout(g.ctx, conn); err != nil {
			g.Logger.Error("Failed to set connection timeout", producer.ErrAttr(err))
		}

		var handlerName string
		switch rule.Type {
		case "proxy_tcp":
			handlerName = rule.Type
		default:
			handlerName = rule.Target
		}

		if hfunc, ok := g.tcpProtocolHandlers[handlerName]; ok {
			go func() {
				if err := hfunc(g.ctx, conn, md); err != nil {
					g.Logger.Error("Failed to handle ", producer.ErrAttr(err), slog.String("handler", handlerName))
				}
			}()
		}
	}
}

// Start the listener, this blocks for new connections
func (g *Glutton) Start() error {
	g.startMonitor()

	sshPort := viper.GetUint32("ports.ssh")
	if err := setTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "tcp", uint32(g.Server.tcpPort), sshPort); err != nil {
		return err
	}

	if err := setTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "udp", uint32(g.Server.udpPort), sshPort); err != nil {
		return err
	}

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go g.udpListen(wg)
	go g.tcpListen()

	wg.Wait()

	return nil
}

func (g *Glutton) makeID() error {
	filePath := filepath.Join(viper.GetString("var-dir"), "glutton.id")
	if err := os.MkdirAll(viper.GetString("var-dir"), 0744); err != nil {
		return fmt.Errorf("failed to create var-dir: %w", err)
	}
	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			g.id = uuid.New()
			data, err := g.id.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal UUID: %w", err)
			}
			if err := os.WriteFile(filePath, data, 0744); err != nil {
				return fmt.Errorf("failed to create new PID file: %w", err)
			}
			return nil
		}
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

func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func (g *Glutton) sanitizePayload(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}
	replASCII := []byte("1.2.3.4")
	replUTF16 := utf16LE("1.2.3.4")
	for _, ip := range g.publicAddrs {
		s := ip.String()
		payload = bytes.ReplaceAll(payload, []byte(s), replASCII)
		payload = bytes.ReplaceAll(payload, utf16LE(s), replUTF16)
	}
	return payload
}

func (g *Glutton) ProduceTCP(handler string, conn net.Conn, md connection.Metadata, payload []byte, decoded interface{}) error {
	if md.Rule != nil && !md.Rule.ShouldProduce() {
		return nil
	}
	if g.Producer != nil {
		payload = g.sanitizePayload(payload)
		decoded = producer.SanitizeDecoded(decoded, g.sanitizePayload)
		return g.Producer.LogTCP(handler, conn, md, payload, decoded)
	}
	return nil
}

func (g *Glutton) ProduceUDP(handler string, srcAddr, dstAddr *net.UDPAddr, md connection.Metadata, payload []byte, decoded interface{}) error {
	if md.Rule != nil && !md.Rule.ShouldProduce() {
		return nil
	}
	if g.Producer != nil {
		payload = g.sanitizePayload(payload)
		decoded = producer.SanitizeDecoded(decoded, g.sanitizePayload)
		return g.Producer.LogUDP(handler, srcAddr, dstAddr, md, payload, decoded)
	}
	return nil
}

// ReplyUDP sends a transparent UDP response to srcAddr, sourced from dstAddr.
func (g *Glutton) ReplyUDP(srcAddr, dstAddr *net.UDPAddr, payload []byte) error {
	if srcAddr == nil || dstAddr == nil {
		return fmt.Errorf("nil udp address")
	}
	conn, err := tproxy.DialUDP("udp4", dstAddr, srcAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(payload)
	return err
}

// Shutdown the packet processor
func (g *Glutton) Shutdown() {
	g.cancel() // close all connection

	g.Logger.Info("Flushing TCP iptables")
	if err := flushTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "tcp", uint32(g.Server.tcpPort), uint32(viper.GetInt("ports.ssh"))); err != nil {
		g.Logger.Error("Failed to drop tcp iptables", producer.ErrAttr(err))
	}
	g.Logger.Info("Flushing UDP iptables")
	if err := flushTProxyIPTables(viper.GetString("interface"), g.publicAddrs[0].String(), "udp", uint32(g.Server.udpPort), uint32(viper.GetInt("ports.ssh"))); err != nil {
		g.Logger.Error("Failed to drop udp iptables", producer.ErrAttr(err))
	}
	if viper.GetBool("spicy.enabled") {
		g.Logger.Info("Cleaning up and shutting down Spicy and HILTI runtimes")
		if err := spicy.Cleanup(); err != nil {
			g.Logger.Error("Failed to clean up Spicy and HILTI runtimes", producer.ErrAttr(err))
		}
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
