package udp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/itp"
	"github.com/stretchr/testify/require"
)

// Synthetic fixtures: no captured ITP traffic exists yet, so datagrams are
// built from the Raven II itp_teleoperation.h layouts.
func itpPacket(layout string, seq uint32, engaged bool) []byte {
	u := &itp.U{
		Layout:      layout,
		Sequence:    seq,
		PacTyp:      1,
		Version:     43,
		DelX:        [2]int32{10, 0},
		DelY:        [2]int32{0, 0},
		DelZ:        [2]int32{-2, 0},
		ButtonState: [2]int32{1, 0},
		Grasp:       [2]int32{100, 0},
	}
	if engaged {
		u.SurgeonMode = itp.SurgeonEngaged
	}
	u.Checksum = u.ExpectedChecksum()
	return u.Marshal()
}

// resetITP gives the test a fresh stream table and a clock it can advance.
func resetITP(t *testing.T) *time.Time {
	t.Helper()
	oldState, oldNow := itpState, itpNow
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	itpState = &itpStreams{streams: map[string]*itpStream{}}
	itpNow = func() time.Time { return now }
	t.Cleanup(func() { itpState, itpNow = oldState, oldNow })
	return &now
}

var (
	itpSrc = &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 40000}
	itpDst = &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: itp.Port}
)

func itpBool(b bool) *bool { return &b }

func TestHandleITPV043Engaged(t *testing.T) {
	resetITP(t)
	h := &recordingHoneypot{}
	payload := itpPacket(itp.LayoutV043, 100, true)

	err := HandleITP(context.Background(), itpSrc, itpDst, payload, connection.Metadata{}, testLogger{}, h)
	require.NoError(t, err)
	require.Len(t, h.produced, 1)
	require.Equal(t, "itp", h.produced[0].handler)
	require.Equal(t, payload, h.produced[0].payload)
	require.Equal(t, connection.EndHandlerClose, h.produced[0].endReason)
	require.Len(t, h.replies, 1)
	require.Len(t, h.replies[0], itp.SizeV)

	// checksum = 1 (engaged) + 10 - 2 + 1 (button) + 100 (seq)
	require.Equal(t, []parsedITP{
		{
			Direction:      "read",
			Command:        "u_struct",
			Layout:         itp.LayoutV043,
			Sequence:       100,
			SequenceStatus: itp.SeqNew,
			PacTyp:         1,
			Version:        43,
			SurgeonMode:    1,
			Checksum:       110,
			ChecksumOK:     itpBool(true),
			ButtonState:    []int32{1, 0},
			Grasp:          []int32{100, 0},
			Packets:        1,
			Payload:        payload,
		},
		{
			Direction:    "write",
			Command:      "v_struct",
			Status:       "PEDAL_DN",
			Runlevel:     "PEDAL_DN",
			Sequence:     1,
			LastSequence: 100,
			PacTyp:       1,
			Version:      43,
			Checksum:     itp.RunlevelPedalD + 1,
			Payload:      h.replies[0],
		},
	}, h.produced[0].decoded)

	v, err := itp.ParseV(h.replies[0])
	require.NoError(t, err)
	require.Equal(t, uint32(100), v.LastSequence)
	require.Equal(t, int32(itp.RunlevelPedalD), v.Runlevel)
}

func TestHandleITPRaven2Disengaged(t *testing.T) {
	resetITP(t)
	h := &recordingHoneypot{}
	payload := itpPacket(itp.LayoutRaven2, 5, false)
	payload[len(payload)-1] ^= 0xff // break the checksum

	require.NoError(t, HandleITP(context.Background(), itpSrc, itpDst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	events := h.produced[0].decoded.([]parsedITP)
	require.Len(t, events, 2)
	require.Equal(t, itp.LayoutRaven2, events[0].Layout)
	require.Equal(t, itpBool(false), events[0].ChecksumOK)
	require.Equal(t, "PEDAL_UP", events[1].Status)
	v, err := itp.ParseV(h.replies[0])
	require.NoError(t, err)
	require.Equal(t, int32(itp.RunlevelPedalU), v.Runlevel)
}

func TestHandleITPSequenceZeroReflects(t *testing.T) {
	resetITP(t)
	h := &recordingHoneypot{}
	payload := itpPacket(itp.LayoutV043, 0, false)

	require.NoError(t, HandleITP(context.Background(), itpSrc, itpDst, payload, connection.Metadata{}, testLogger{}, h))
	require.Len(t, h.produced, 1)
	require.Equal(t, [][]byte{payload}, h.replies)
	events := h.produced[0].decoded.([]parsedITP)
	require.Len(t, events, 2)
	require.Equal(t, itp.SeqReflect, events[0].SequenceStatus)
	require.Equal(t, parsedITP{Direction: "write", Command: "reflect", Status: "reflect", Payload: payload}, events[1])
}

func TestHandleITPStreamSequence(t *testing.T) {
	resetITP(t)
	var statuses []string
	var replySeqs []uint32
	for _, seq := range []uint32{10, 11, 11, 15, 3} {
		h := &recordingHoneypot{}
		require.NoError(t, HandleITP(context.Background(), itpSrc, itpDst, itpPacket(itp.LayoutV043, seq, true), connection.Metadata{}, testLogger{}, h))
		require.Len(t, h.produced, 1)
		events := h.produced[0].decoded.([]parsedITP)
		statuses = append(statuses, events[0].SequenceStatus)
		replySeqs = append(replySeqs, events[1].Sequence)
	}
	require.Equal(t, []string{itp.SeqNew, itp.SeqValid, itp.SeqDuplicate, itp.SeqSkipped, itp.SeqOutOfOrder}, statuses)
	require.Equal(t, []uint32{1, 2, 3, 4, 5}, replySeqs)

	// a different source port is a different master
	h := &recordingHoneypot{}
	other := &net.UDPAddr{IP: itpSrc.IP, Port: itpSrc.Port + 1}
	require.NoError(t, HandleITP(context.Background(), other, itpDst, itpPacket(itp.LayoutV043, 3, true), connection.Metadata{}, testLogger{}, h))
	require.Equal(t, itp.SeqNew, h.produced[0].decoded.([]parsedITP)[0].SequenceStatus)
}

func TestHandleITPStreamExpires(t *testing.T) {
	now := resetITP(t)

	send := func(seq uint32) parsedITP {
		h := &recordingHoneypot{}
		require.NoError(t, HandleITP(context.Background(), itpSrc, itpDst, itpPacket(itp.LayoutV043, seq, true), connection.Metadata{}, testLogger{}, h))
		return h.produced[0].decoded.([]parsedITP)[0]
	}
	require.Equal(t, itp.SeqNew, send(10).SequenceStatus)
	*now = now.Add(itpStreamTimeout - time.Millisecond)
	require.Equal(t, 2, send(11).Packets)
	*now = now.Add(itpStreamTimeout)
	f := send(12)
	require.Equal(t, itp.SeqNew, f.SequenceStatus)
	require.Equal(t, 1, f.Packets)
}

func TestITPStreamsBounded(t *testing.T) {
	s := &itpStreams{streams: map[string]*itpStream{}}
	base := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	for i := 0; i < maxITPStreams+10; i++ {
		s.next(fmt.Sprintf("203.0.113.1:%d", i), 1, base.Add(time.Duration(i)*time.Millisecond))
	}
	require.Len(t, s.streams, maxITPStreams)
	require.NotContains(t, s.streams, "203.0.113.1:0", "oldest stream evicted")
	require.Contains(t, s.streams, fmt.Sprintf("203.0.113.1:%d", maxITPStreams+9))
}

func TestHandleITPMalformedStillProduces(t *testing.T) {
	resetITP(t)
	big := make([]byte, maxITPPayload+50)
	for _, payload := range [][]byte{nil, {0x01, 0x00, 0x00, 0x00}, make([]byte, itp.SizeV043-1), make([]byte, itp.SizeV043+1), big} {
		h := &recordingHoneypot{}
		require.NoError(t, HandleITP(context.Background(), itpSrc, itpDst, payload, connection.Metadata{}, testLogger{}, h))
		require.Len(t, h.produced, 1)
		require.Equal(t, "itp", h.produced[0].handler)
		require.Empty(t, h.replies)
		events := h.produced[0].decoded.([]parsedITP)
		require.Len(t, events, 1)
		require.Equal(t, "read", events[0].Direction)
		require.Equal(t, "UNKNOWN", events[0].Command)
		require.Equal(t, len(payload) > maxITPPayload, events[0].Truncated)
		require.Len(t, events[0].Payload, min(len(payload), maxITPPayload))
	}
	require.Empty(t, itpState.streams)
}
