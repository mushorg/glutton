package rtp

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// packet builds an RTP v2 packet.
func packet(pt uint8, marker bool, seq uint16, ts, ssrc uint32, payload []byte) []byte {
	b := []byte{0x80, pt, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if marker {
		b[1] |= 0x80
	}
	binary.BigEndian.PutUint16(b[2:], seq)
	binary.BigEndian.PutUint32(b[4:], ts)
	binary.BigEndian.PutUint32(b[8:], ssrc)
	return append(b, payload...)
}

type unlimited struct{ taken int }

func (u *unlimited) Take(n int) bool { u.taken += n; return true }

type capped struct{ left int }

func (c *capped) Take(n int) bool {
	if n > c.left {
		return false
	}
	c.left -= n
	return true
}

func TestParse(t *testing.T) {
	h, payload, err := Parse(packet(PCMU, true, 7, 160, 0xdeadbeef, []byte{1, 2, 3}))
	require.NoError(t, err)
	require.Equal(t, Header{Marker: true, PayloadType: PCMU, Seq: 7, Timestamp: 160, SSRC: 0xdeadbeef}, h)
	require.Equal(t, []byte{1, 2, 3}, payload)
}

func TestParseCSRCExtensionPadding(t *testing.T) {
	b := packet(PCMA, false, 1, 0, 1, nil)
	b[0] |= 0x20 | 0x10 | 0x01                              // padding, extension, one CSRC
	b = append(b, 0, 0, 0, 9)                               // CSRC
	b = append(b, 0xbe, 0xde, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd) // extension, one word
	b = append(b, 0x11, 0x22, 0, 0, 3)                      // payload + 3 padding bytes
	h, payload, err := Parse(b)
	require.NoError(t, err)
	require.Equal(t, 1, h.CSRCCount)
	require.True(t, h.Extension)
	require.Equal(t, []byte{0x11, 0x22}, payload)
}

func TestParseRejects(t *testing.T) {
	for name, data := range map[string][]byte{
		"short":     {0x80, 0, 0},
		"version 1": append([]byte{0x40}, make([]byte, 11)...),
		"ascii sip": []byte("INVITE sip:1@x SIP/2.0\r\n"),
		"rtcp sr":   append([]byte{0x80, 0xc8, 0, 6}, make([]byte, 24)...),
		"bad pad":   append([]byte{0xa0, 0}, append(make([]byte, 10), 99)...),
		"csrc":      append([]byte{0x8f, 0}, make([]byte, 10)...),
	} {
		_, _, err := Parse(data)
		require.Error(t, err, name)
	}
}

func TestEventDigit(t *testing.T) {
	ev, err := ParseEvent([]byte{11, 0x8a, 0x03, 0x20})
	require.NoError(t, err)
	require.Equal(t, Event{Code: 11, End: true, Volume: 10, Duration: 800}, ev)
	require.Equal(t, "#", ev.Digit())
	require.Equal(t, "", Event{Code: 16}.Digit())
	_, err = ParseEvent([]byte{1})
	require.Error(t, err)
}

func add(t *testing.T, s *Stream, a Allowance, data []byte) {
	t.Helper()
	h, payload, err := Parse(data)
	require.NoError(t, err)
	s.Add(h, payload, a)
}

func TestStreamAudioPlacedByTimestamp(t *testing.T) {
	s := NewStream(1, 101, 1000)
	a := &unlimited{}
	add(t, s, a, packet(PCMU, true, 100, 8000, 1, []byte{1, 2}))
	// seq 101 lost, seq 102 two samples later in time than a gapless stream
	add(t, s, a, packet(PCMU, false, 102, 8004, 1, []byte{5, 6}))
	add(t, s, a, packet(PCMU, false, 102, 8004, 1, []byte{5, 6})) // duplicate

	require.Equal(t, []byte{1, 2, 0xff, 0xff, 5, 6}, s.Audio())
	require.Equal(t, 6, a.taken)
	require.Equal(t, PCMU, s.AudioPT)
	require.Equal(t, 3, s.Packets)
	require.Equal(t, 0, s.Lost()) // the duplicate fills the count
	require.False(t, s.Truncated)
}

func TestStreamLossAcrossWrap(t *testing.T) {
	s := NewStream(1, -1, 1000)
	a := &unlimited{}
	add(t, s, a, packet(PCMA, false, 65534, 0, 1, []byte{1}))
	add(t, s, a, packet(PCMA, false, 1, 3, 1, []byte{4})) // 65535 and 0 lost
	require.Equal(t, 2, s.Lost())
	require.Equal(t, []byte{1, 0xd5, 0xd5, 4}, s.Audio())
}

func TestStreamDTMF(t *testing.T) {
	s := NewStream(1, 101, 1000)
	a := &unlimited{}
	seq := uint16(1)
	press := func(code uint8, ts uint32) {
		// start, continuation, and the end packet sent three times
		for i, flags := range []byte{0x0a, 0x0a, 0x8a, 0x8a, 0x8a} {
			add(t, s, a, packet(101, i == 0, seq, ts, 1, []byte{code, flags, 0, byte(i * 80)}))
			seq++
		}
	}
	press(1, 1000)
	press(2, 2000)
	press(11, 3000)
	press(16, 4000) // flash: not a digit
	press(1, 5000)
	require.Equal(t, "12#1", s.DTMF())
	require.Equal(t, -1, s.AudioPT)
	require.Empty(t, s.Audio())
	require.Equal(t, 25, s.Packets)
}

func TestStreamOtherCodecCountedNotRecorded(t *testing.T) {
	s := NewStream(1, -1, 1000)
	a := &unlimited{}
	add(t, s, a, packet(18, false, 1, 0, 1, []byte{1, 2, 3})) // G.729
	add(t, s, a, packet(18, false, 2, 80, 1, []byte{1, 2, 3}))
	require.Equal(t, 18, s.AudioPT)
	require.Equal(t, 2, s.Packets)
	require.Empty(t, s.Audio())
}

func TestStreamComfortNoiseNotRecorded(t *testing.T) {
	s := NewStream(1, -1, 1000)
	a := &unlimited{}
	add(t, s, a, packet(PCMU, false, 1, 0, 1, []byte{1}))
	add(t, s, a, packet(13, false, 2, 1, 1, []byte{0x40}))
	add(t, s, a, packet(PCMU, false, 3, 3, 1, []byte{3}))
	require.Equal(t, []byte{1, 0xff, 0xff, 3}, s.Audio())
}

func TestStreamCaps(t *testing.T) {
	// per-stream byte cap: a timestamp jump past it is dropped, not allocated
	s := NewStream(1, -1, 4)
	a := &unlimited{}
	add(t, s, a, packet(PCMU, false, 1, 0, 1, []byte{1, 2}))
	add(t, s, a, packet(PCMU, false, 2, 1<<30, 1, []byte{3}))
	require.Equal(t, []byte{1, 2}, s.Audio())
	require.True(t, s.Truncated)

	// allowance exhausted
	s = NewStream(1, -1, 100)
	c := &capped{left: 3}
	add(t, s, c, packet(PCMU, false, 1, 0, 1, []byte{1, 2}))
	add(t, s, c, packet(PCMU, false, 2, 2, 1, []byte{3, 4}))
	require.Equal(t, []byte{1, 2}, s.Audio())
	require.True(t, s.Truncated)

	// reordered packet older than the first audio is skipped
	s = NewStream(1, -1, 100)
	add(t, s, a, packet(PCMU, false, 5, 100, 1, []byte{1}))
	add(t, s, a, packet(PCMU, false, 4, 99, 1, []byte{2}))
	require.Equal(t, []byte{1}, s.Audio())
	require.False(t, s.Truncated)

	// digit cap
	s = NewStream(1, 101, 100)
	for i := range maxDigits + 1 {
		add(t, s, a, packet(101, true, uint16(i), uint32(i*800), 1, []byte{5, 0x8a, 0, 80}))
	}
	require.Len(t, s.DTMF(), maxDigits)
	require.True(t, s.Truncated)
}

func TestWAV(t *testing.T) {
	w := WAV(PCMU, []byte{0xff, 0x7f, 0x00})
	require.Equal(t, "RIFF", string(w[0:4]))
	require.Equal(t, uint32(len(w)-8), binary.LittleEndian.Uint32(w[4:8]))
	require.Equal(t, "WAVEfmt ", string(w[8:16]))
	require.Equal(t, uint32(18), binary.LittleEndian.Uint32(w[16:20]))
	require.Equal(t, uint16(7), binary.LittleEndian.Uint16(w[20:22]))    // µ-law
	require.Equal(t, uint32(8000), binary.LittleEndian.Uint32(w[24:28])) // sample rate
	require.Equal(t, "fact", string(w[38:42]))
	require.Equal(t, uint32(3), binary.LittleEndian.Uint32(w[46:50]))
	require.Equal(t, "data", string(w[50:54]))
	require.Equal(t, uint32(3), binary.LittleEndian.Uint32(w[54:58]))
	require.Equal(t, []byte{0xff, 0x7f, 0x00, 0x00}, w[58:]) // pad byte
	require.Equal(t, uint16(6), binary.LittleEndian.Uint16(WAV(PCMA, nil)[20:22]))
}

func TestParseSDPAudio(t *testing.T) {
	offer := "v=0\r\no=1828 1 2 IN IP4 84.32.70.222\r\ns=SIP Call\r\nc=IN IP4 84.32.70.222\r\nt=0 0\r\n" +
		"m=audio 26476 RTP/AVP 111 9 8 0 101\r\na=rtpmap:111 opus/48000/2\r\na=rtpmap:101 telephone-event/8000\r\n" +
		"m=video 30000 RTP/AVP 96\r\nc=IN IP4 192.0.2.9\r\na=rtpmap:96 H264/90000\r\n"
	m, ok := ParseSDPAudio(offer)
	require.True(t, ok)
	require.Equal(t, 26476, m.Port)
	require.True(t, m.IP.Equal(net.ParseIP("84.32.70.222")))
	require.Equal(t, "opus", m.Names[111])
	require.Equal(t, "PCMU", m.Names[PCMU])
	require.Equal(t, 101, m.DTMF())
	require.NotContains(t, m.Names, uint8(96))

	m, ok = ParseSDPAudio("v=0\nc=IN IP4 0.0.0.0\nm=audio 4000 RTP/AVP 0\nc=IN IP4 192.0.2.7\n")
	require.True(t, ok)
	require.True(t, m.IP.Equal(net.ParseIP("192.0.2.7")))
	require.Equal(t, -1, m.DTMF())

	_, ok = ParseSDPAudio("v=0\r\nm=video 1 RTP/AVP 96\r\n")
	require.False(t, ok)
	_, ok = ParseSDPAudio("")
	require.False(t, ok)
}
