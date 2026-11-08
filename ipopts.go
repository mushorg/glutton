package glutton

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/ipopts"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/spf13/viper"
)

// watchIPOpts passively captures IPv4 TCP packets that carry IP options and
// produces one event per flow. Soft-fails if the capture cannot open so the
// sensor keeps running without the watcher.
func (g *Glutton) watchIPOpts() {
	if !viper.GetBool("ipopts_watch.enabled") {
		return
	}
	iface := viper.GetString("interface")
	snaplen := viper.GetInt("ipopts_watch.snaplen")
	if snaplen <= 0 {
		snaplen = 256
	}
	capture, err := ipopts.OpenCapture(iface, snaplen)
	if err != nil {
		g.Logger.Warn("ipopts watcher disabled: failed to open capture",
			slog.String("interface", iface),
			slog.String("reporter", "glutton"),
			producer.ErrAttr(err))
		return
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
		slog.String("reporter", "glutton"))

	// The reader decodes in its own goroutine because ReadPacket reuses its
	// buffer; decoded packets own their bytes.
	type capturedPacket struct {
		pkt       *ipopts.Packet
		direction string
	}
	packets := make(chan capturedPacket, 64)
	go func() {
		defer close(packets)
		for {
			data, outgoing, err := capture.ReadPacket()
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
					g.Logger.Warn("ipopts watcher stopped: capture read failed",
						slog.String("reporter", "glutton"),
						producer.ErrAttr(err))
				}
				return
			}
			pkt, ok := ipopts.DecodeIPv4(data)
			if !ok {
				continue
			}
			direction := "read"
			if outgoing {
				direction = "write"
			}
			select {
			case packets <- capturedPacket{pkt, direction}:
			case <-g.ctx.Done():
				return
			}
		}
	}()
	defer capture.Close()

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
		case p, ok := <-packets:
			if !ok {
				for _, flow := range tracker.Close() {
					g.produceIPOptsFlow(flow)
				}
				return
			}
			for _, flow := range tracker.Add(time.Now(), p.direction, p.pkt) {
				g.produceIPOptsFlow(flow)
			}
		}
	}
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
