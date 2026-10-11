package udp

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/udp/rtp"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// rtpPacket builds a synthetic RTP v2 packet.
func rtpPacket(pt uint8, seq uint16, ts, ssrc uint32, payload []byte) []byte {
	b := []byte{0x80, pt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:], seq)
	binary.BigEndian.PutUint32(b[4:], ts)
	binary.BigEndian.PutUint32(b[8:], ssrc)
	return append(b, payload...)
}

// stubSIPRecordings captures stored WAV files instead of writing them.
func stubSIPRecordings(t *testing.T) *[][]byte {
	t.Helper()
	stored := &[][]byte{}
	sipMediaBytes.Store(0)
	orig := sipStoreRecording
	sipStoreRecording = func(data []byte) (string, error) {
		*stored = append(*stored, append([]byte(nil), data...))
		return "hash" + strconv.Itoa(len(*stored)), nil
	}
	t.Cleanup(func() {
		sipStoreRecording = orig
		sipMediaBytes.Store(0)
	})
	return stored
}

// answerCall sends the pplsip INVITE, lets it ring and returns the media
// port of the 200 OK's SDP answer.
func answerCall(t *testing.T, h *recordingHoneypot, timers *fakeSIPTimers, invite []byte) int {
	t.Helper()
	sendSIP(t, h, pplsipSrc, invite)
	timers.fire(t, sipRing)
	require.Len(t, h.replies, 3)
	ok := string(h.replies[2])
	require.True(t, strings.HasPrefix(ok, "SIP/2.0 200 OK\r\n"))
	_, body, _ := strings.Cut(ok, "\r\n\r\n")
	m, found := rtp.ParseSDPAudio(body)
	require.True(t, found)
	return m.Port
}

func sendUDP(t *testing.T, h *recordingHoneypot, src *net.UDPAddr, port int, data []byte) {
	t.Helper()
	dst := &net.UDPAddr{IP: pplsipDst.IP, Port: port}
	require.NoError(t, HandleUDP(context.Background(), src, dst, data, connection.Metadata{}, testLogger{}, h))
}

// withOfferAddress rewrites the pplsip offer's c= line, fixing Content-Length.
func withOfferAddress(ip string) []byte {
	head, body, _ := strings.Cut(string(pplsipInviteRead1), "\r\n\r\n")
	body = strings.Replace(body, "c=IN IP4 0.0.0.0", "c=IN IP4 "+ip, 1)
	head = strings.Replace(head, "Content-Length: 211", "Content-Length: "+strconv.Itoa(len(body)), 1)
	return []byte(head + "\r\n\r\n" + body)
}

func TestHandleSIPDialogRecordsMedia(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	stored := stubSIPRecordings(t)
	h := &recordingHoneypot{}
	port := answerCall(t, h, timers, pplsipInviteRead1)
	sendSIP(t, h, pplsipSrc, pplsipInDialog("ACK", 1, pplsipCallID))

	media := &net.UDPAddr{IP: pplsipSrc.IP, Port: 25282}
	const ssrc = 0x1234abcd
	// 3 audio packets of 160 µ-law samples; seq 12 is lost
	for i, seq := range []uint16{10, 11, 13} {
		ts := uint32(seq-10) * 160
		sendUDP(t, h, media, port, rtpPacket(rtp.PCMU, seq, ts, ssrc, []byte(strings.Repeat(string(rune('a'+i)), 160))))
	}
	// DTMF "1" then "#": start packet plus repeated end packets
	seq := uint16(14)
	for _, ev := range []struct {
		code uint8
		ts   uint32
	}{{1, 640}, {11, 1280}} {
		for _, flags := range []byte{0x0a, 0x8a, 0x8a, 0x8a} {
			sendUDP(t, h, media, port, rtpPacket(101, seq, ev.ts, ssrc, []byte{ev.code, flags, 0, 160}))
			seq++
		}
	}
	require.Empty(t, h.produced, "RTP must not produce udp events")
	require.Equal(t, int64(640), sipMediaBytes.Load()) // 4 packets of audio time, the lost one as silence

	sendSIP(t, h, pplsipSrc, pplsipInDialog("BYE", 2, pplsipCallID))
	require.Len(t, h.produced, 1)
	require.Equal(t, "sip", h.produced[0].handler)
	require.Equal(t, connection.EndClientClose, h.produced[0].endReason)
	require.Equal(t, int64(0), sipMediaBytes.Load(), "budget released")

	events := h.produced[0].decoded.([]parsedSIP)
	require.Equal(t, []string{"read INVITE", "write ", "write ", "write ", "read ACK", "read BYE", "write ", "read rtp"}, frameCommands(events))
	require.Equal(t, parsedSIP{
		Direction:   "read",
		Command:     "rtp",
		CallID:      pplsipCallID,
		SSRC:        "1234abcd",
		Codec:       "PCMU",
		Packets:     11,
		Lost:        1,
		DurationMs:  80,
		DTMF:        "1#",
		PayloadHash: "hash1",
	}, events[len(events)-1])

	require.Len(t, *stored, 1)
	wav := (*stored)[0]
	samples := wav[58:]
	require.Equal(t, rtp.WAV(rtp.PCMU, samples), wav)
	require.Equal(t, strings.Repeat("a", 160)+strings.Repeat("b", 160)+strings.Repeat("\xff", 160)+strings.Repeat("c", 160), string(samples))

	// the binding ended with the call: late RTP goes to the catch-all
	t.Chdir(t.TempDir()) // the generic handler stores payloads in ./payloads
	sendUDP(t, h, media, port, rtpPacket(rtp.PCMU, 30, 3200, ssrc, []byte{1}))
	require.Len(t, h.produced, 2)
	require.Equal(t, "udp", h.produced[1].handler)
}

func frameCommands(events []parsedSIP) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Direction + " " + e.Command
	}
	return out
}

func TestHandleSIPMediaOnlyFromCaller(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	stubSIPRecordings(t)
	t.Chdir(t.TempDir())
	h := &recordingHoneypot{}
	port := answerCall(t, h, timers, withOfferAddress("198.51.100.7"))

	pkt := rtpPacket(rtp.PCMU, 1, 0, 7, []byte{1, 2})
	// another IP sending to the media port is not part of the call
	sendUDP(t, h, &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4000}, port, pkt)
	// non-RTP from the caller to the media port is not media either
	sendUDP(t, h, &net.UDPAddr{IP: pplsipSrc.IP, Port: 4000}, port, []byte("hello"))
	// RTP from the caller to some other port
	sendUDP(t, h, &net.UDPAddr{IP: pplsipSrc.IP, Port: 4000}, port+2, pkt)
	require.Len(t, h.produced, 3)
	for _, p := range h.produced {
		require.Equal(t, "udp", p.handler)
	}

	// the offer's c= address (a media relay) and the signaling IP both count
	sendUDP(t, h, &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 4000}, port, pkt)
	sendUDP(t, h, &net.UDPAddr{IP: pplsipSrc.IP, Port: 4002}, port, rtpPacket(rtp.PCMU, 1, 0, 8, []byte{3}))
	require.Len(t, h.produced, 3)

	timers.fire(t, time.Minute) // idle: no ACK/BYE handling needed for the check
	require.Len(t, h.produced, 4)
	events := h.produced[3].decoded.([]parsedSIP)
	rtpFrames := events[len(events)-2:]
	require.Equal(t, "00000007", rtpFrames[0].SSRC)
	require.Equal(t, "00000008", rtpFrames[1].SSRC)
}

func TestHandleSIPMediaKeepsCallAlive(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	stubSIPRecordings(t)
	h := &recordingHoneypot{}
	port := answerCall(t, h, timers, pplsipInviteRead1)
	sendSIP(t, h, pplsipSrc, pplsipInDialog("ACK", 1, pplsipCallID))
	require.Equal(t, []time.Duration{time.Minute}, timers.pending())

	idle := func() *fakeSIPTimer {
		timers.mu.Lock()
		defer timers.mu.Unlock()
		for _, ft := range timers.timers {
			if !ft.stopped && !ft.fired && ft.d == time.Minute {
				return ft
			}
		}
		return nil
	}
	before := idle()
	sendUDP(t, h, &net.UDPAddr{IP: pplsipSrc.IP, Port: 25282}, port, rtpPacket(rtp.PCMU, 1, 0, 1, []byte{1}))
	require.NotSame(t, before, idle(), "media re-arms the idle timer")
	require.Equal(t, []time.Duration{time.Minute}, timers.pending())
}

func TestHandleSIPMediaCaps(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	stubSIPRecordings(t)
	h := &recordingHoneypot{}
	port := answerCall(t, h, timers, pplsipInviteRead1)
	media := &net.UDPAddr{IP: pplsipSrc.IP, Port: 25282}

	// streams beyond maxRTPStreams are dropped, and the last frame says so
	for ssrc := range uint32(maxRTPStreams + 2) {
		sendUDP(t, h, media, port, rtpPacket(rtp.PCMU, 1, 0, ssrc, []byte{1}))
	}
	// a timestamp jump past the per-call cap is not recorded
	sendUDP(t, h, media, port, rtpPacket(rtp.PCMU, 2, maxRTPCallBytes, 0, []byte{2}))
	require.Empty(t, h.produced)

	timers.fire(t, time.Minute)
	require.Len(t, h.produced, 1)
	events := h.produced[0].decoded.([]parsedSIP)
	rtpFrames := events[len(events)-maxRTPStreams:]
	require.Equal(t, "rtp", rtpFrames[0].Command)
	require.True(t, rtpFrames[0].Truncated, "cap on stream 0")
	require.False(t, rtpFrames[1].Truncated)
	require.True(t, rtpFrames[maxRTPStreams-1].Truncated, "dropped streams")
	require.Equal(t, int64(0), sipMediaBytes.Load())
}

func TestHandleSIPMediaDisabled(t *testing.T) {
	stubSIPResponder(t)
	timers := stubSIPDialogs(t)
	stubSIPRecordings(t)
	t.Chdir(t.TempDir())
	viper.Set("sip.record_media", false)
	t.Cleanup(func() { viper.Set("sip.record_media", true) })
	h := &recordingHoneypot{}
	port := answerCall(t, h, timers, pplsipInviteRead1)

	sendUDP(t, h, &net.UDPAddr{IP: pplsipSrc.IP, Port: 25282}, port, rtpPacket(rtp.PCMU, 1, 0, 1, []byte{1}))
	require.Len(t, h.produced, 1)
	require.Equal(t, "udp", h.produced[0].handler)
}

func TestHandleSIPRejectedCallBindsNoMedia(t *testing.T) {
	stubSIPResponder(t)
	stubSIPDialogs(t)
	stubSIPRecordings(t)
	sipRejectLimit = 2
	stubSIPRecall(t)
	h := &recordingHoneypot{}
	sendSIP(t, h, pplsipSrc, pplsipInviteRead1)
	require.True(t, strings.HasPrefix(string(h.replies[len(h.replies)-1]), "SIP/2.0 404 Not Found\r\n"))
	require.Empty(t, sipMedia.bindings)
}
