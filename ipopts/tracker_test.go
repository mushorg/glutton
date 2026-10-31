package ipopts

import (
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func testPkt(srcIP, dstIP string, srcPort, dstPort uint16, cmd string) *Packet {
	return &Packet{
		SrcIP:   net.ParseIP(srcIP).To4(),
		DstIP:   net.ParseIP(dstIP).To4(),
		SrcPort: srcPort,
		DstPort: dstPort,
		Frame: Frame{
			Command: cmd,
			Options: []Option{{Type: 1, Name: "NOP", Length: 1}},
			Payload: []byte{0x45},
		},
	}
}

func TestTrackerReadWriteSameFlow(t *testing.T) {
	tr := NewTracker(Config{Idle: time.Minute, MaxFlows: 10, MaxFrames: 10})
	now := time.Unix(1000, 0)

	flushed := tr.Add(now, "read", testPkt("203.0.113.10", "192.0.2.10", 54321, 80, "SYN"))
	require.Empty(t, flushed)

	// Outbound SYN-ACK as seen on the wire: sensor → attacker.
	flushed = tr.Add(now.Add(time.Millisecond), "write", testPkt("192.0.2.10", "203.0.113.10", 80, 54321, "SYN-ACK"))
	require.Empty(t, flushed)

	got := tr.Expire(now.Add(2 * time.Minute))
	require.Len(t, got, 1)
	require.Equal(t, connection.EndTimeout, got[0].EndReason)
	require.Equal(t, "203.0.113.10", got[0].SrcIP.String())
	require.Equal(t, "192.0.2.10", got[0].DstIP.String())
	require.EqualValues(t, 54321, got[0].SrcPort)
	require.EqualValues(t, 80, got[0].DstPort)
	require.Len(t, got[0].Frames, 2)
	require.Equal(t, "read", got[0].Frames[0].Direction)
	require.Equal(t, "SYN", got[0].Frames[0].Command)
	require.Equal(t, "write", got[0].Frames[1].Direction)
	require.Equal(t, "SYN-ACK", got[0].Frames[1].Command)
}

func TestTrackerMaxFrames(t *testing.T) {
	tr := NewTracker(Config{Idle: time.Minute, MaxFlows: 10, MaxFrames: 2})
	now := time.Unix(1, 0)
	require.Empty(t, tr.Add(now, "read", testPkt("1.1.1.1", "2.2.2.2", 1, 2, "SYN")))
	flushed := tr.Add(now.Add(time.Second), "read", testPkt("1.1.1.1", "2.2.2.2", 1, 2, "ACK"))
	require.Len(t, flushed, 1)
	require.Equal(t, connection.EndMaxFrames, flushed[0].EndReason)
	require.Len(t, flushed[0].Frames, 2)
	require.Empty(t, tr.Expire(now.Add(time.Hour)))
}

func TestTrackerMaxFlowsEvictsLRU(t *testing.T) {
	tr := NewTracker(Config{Idle: time.Minute, MaxFlows: 2, MaxFrames: 10})
	now := time.Unix(1, 0)
	require.Empty(t, tr.Add(now, "read", testPkt("1.1.1.1", "9.9.9.9", 1, 80, "SYN")))
	require.Empty(t, tr.Add(now.Add(time.Second), "read", testPkt("2.2.2.2", "9.9.9.9", 2, 80, "SYN")))

	flushed := tr.Add(now.Add(2*time.Second), "read", testPkt("3.3.3.3", "9.9.9.9", 3, 80, "SYN"))
	require.Len(t, flushed, 1)
	require.Equal(t, connection.EndEvicted, flushed[0].EndReason)
	require.Equal(t, "1.1.1.1", flushed[0].SrcIP.String())

	remaining := tr.Close()
	require.Len(t, remaining, 2)
	srcs := map[string]bool{}
	for _, f := range remaining {
		require.Equal(t, connection.EndHandlerClose, f.EndReason)
		srcs[f.SrcIP.String()] = true
	}
	require.True(t, srcs["2.2.2.2"])
	require.True(t, srcs["3.3.3.3"])
}

func TestTrackerIdleExpire(t *testing.T) {
	tr := NewTracker(Config{Idle: 5 * time.Second, MaxFlows: 10, MaxFrames: 10})
	now := time.Unix(10, 0)
	require.Empty(t, tr.Add(now, "read", testPkt("1.1.1.1", "2.2.2.2", 10, 20, "SYN")))
	require.Empty(t, tr.Expire(now.Add(4*time.Second)))
	got := tr.Expire(now.Add(6 * time.Second))
	require.Len(t, got, 1)
	require.Equal(t, connection.EndTimeout, got[0].EndReason)
}

func TestTrackerDefaults(t *testing.T) {
	tr := NewTracker(Config{})
	require.Equal(t, 5*time.Second, tr.cfg.Idle)
	require.Equal(t, 1024, tr.cfg.MaxFlows)
	require.Equal(t, 32, tr.cfg.MaxFrames)
}
