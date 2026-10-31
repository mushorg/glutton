package glutton

import (
	"log/slog"
	"net"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/ipopts"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/spf13/viper"
)

const ipoptsBPF = "ip and tcp and (ip[0] & 0x0f) > 5"

// watchIPOpts passively captures IPv4 TCP packets that carry IP options and
// produces one event per flow. Soft-fails if pcap cannot open so the sensor
// keeps running without the watcher.
func (g *Glutton) watchIPOpts() {
	if !viper.GetBool("ipopts_watch.enabled") {
		return
	}
	iface := viper.GetString("interface")
	snaplen := viper.GetInt("ipopts_watch.snaplen")
	if snaplen <= 0 {
		snaplen = 256
	}
	handle, err := pcap.OpenLive(iface, int32(snaplen), false, 500*time.Millisecond)
	if err != nil {
		g.Logger.Warn("ipopts watcher disabled: failed to open pcap",
			slog.String("interface", iface),
			slog.String("reporter", "glutton"),
			producer.ErrAttr(err))
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(ipoptsBPF); err != nil {
		g.Logger.Warn("ipopts watcher disabled: failed to set BPF filter",
			slog.String("reporter", "glutton"),
			producer.ErrAttr(err))
		return
	}

	inboundOnly := false
	if err := handle.SetDirection(pcap.DirectionIn); err != nil {
		g.Logger.Debug("ipopts watcher: SetDirection not supported, classifying with publicAddrs",
			slog.String("reporter", "glutton"),
			producer.ErrAttr(err))
	} else {
		inboundOnly = true
	}

	idleSecs := viper.GetInt("ipopts_watch.idle_seconds")
	if idleSecs <= 0 {
		idleSecs = 5
	}
	tracker := ipopts.NewTracker(ipopts.Config{
		Idle:      time.Duration(idleSecs) * time.Second,
		MaxFlows:  viper.GetInt("ipopts_watch.max_flows"),
		MaxFrames: viper.GetInt("ipopts_watch.max_frames"),
	})

	g.Logger.Info("ipopts watcher started",
		slog.String("interface", iface),
		slog.Int("snaplen", snaplen),
		slog.Bool("inbound_only", inboundOnly),
		slog.String("reporter", "glutton"))

	linkType := handle.LinkType()
	src := gopacket.NewPacketSource(handle, linkType)
	packets := src.Packets()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-g.ctx.Done():
			for _, flow := range tracker.Close() {
				g.produceIPOptsFlow(flow)
			}
			return
		case <-ticker.C:
			for _, flow := range tracker.Expire(time.Now()) {
				g.produceIPOptsFlow(flow)
			}
		case packet, ok := <-packets:
			if !ok {
				for _, flow := range tracker.Close() {
					g.produceIPOptsFlow(flow)
				}
				return
			}
			data := packet.Data()
			pkt, decoded := ipopts.Decode(data, linkType)
			if !decoded {
				continue
			}
			direction := "read"
			if !inboundOnly {
				direction = g.ipoptsDirection(pkt.SrcIP)
			}
			now := time.Now()
			for _, flow := range tracker.Add(now, direction, pkt) {
				g.produceIPOptsFlow(flow)
			}
		}
	}
}

func (g *Glutton) ipoptsDirection(srcIP net.IP) string {
	if g.isPublicAddr(srcIP) {
		return "write"
	}
	return "read"
}

func (g *Glutton) isPublicAddr(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, pub := range g.publicAddrs {
		if pub != nil && pub.Equal(ip) {
			return true
		}
	}
	return false
}

func (g *Glutton) produceIPOptsFlow(flow ipopts.Flow) {
	md := connection.Metadata{
		Added:      flow.Started,
		TargetPort: flow.DstPort,
		TargetIP:   flow.DstIP.String(),
		EndReason:  flow.EndReason,
	}
	conn := &ipoptsAddrConn{
		remote: &net.TCPAddr{IP: flow.SrcIP, Port: int(flow.SrcPort)},
		local:  &net.TCPAddr{IP: flow.DstIP, Port: int(flow.DstPort)},
	}
	payload := helpers.FirstOrEmpty(flow.Frames).Payload
	if err := g.ProduceTCP("ipopts", conn, md, payload, flow.Frames); err != nil {
		g.Logger.Error("Failed to produce message",
			slog.String("protocol", "ipopts"),
			producer.ErrAttr(err))
	}
}

// ipoptsAddrConn is a net.Conn shim so ProduceTCP can read src/dst addresses
// for a packet flow that never became a userspace connection.
type ipoptsAddrConn struct {
	remote net.Addr
	local  net.Addr
}

func (c *ipoptsAddrConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *ipoptsAddrConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *ipoptsAddrConn) Close() error                     { return nil }
func (c *ipoptsAddrConn) LocalAddr() net.Addr              { return c.local }
func (c *ipoptsAddrConn) RemoteAddr() net.Addr             { return c.remote }
func (c *ipoptsAddrConn) SetDeadline(time.Time) error      { return nil }
func (c *ipoptsAddrConn) SetReadDeadline(time.Time) error  { return nil }
func (c *ipoptsAddrConn) SetWriteDeadline(time.Time) error { return nil }
