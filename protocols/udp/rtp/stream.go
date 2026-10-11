package rtp

import "encoding/binary"

// maxDigits caps the DTMF digits kept per stream.
const maxDigits = 64

// Allowance hands out the bytes a recording may grow by. Take reports false
// once the budget is spent; the stream then stops recording audio.
type Allowance interface {
	Take(n int) bool
}

// Stream collects one SSRC of a call: packet and loss counts, DTMF digits,
// and G.711 audio placed at its RTP timestamp, so gaps and lost packets
// become silence and the recording keeps real time.
type Stream struct {
	SSRC    uint32
	Packets int
	// AudioPT is the payload type of the first non-DTMF packet, or -1.
	AudioPT int
	// Truncated is set when audio or digits were dropped by a cap.
	Truncated bool

	dtmfPT   int
	maxBytes int

	seqStarted bool
	lastExt    int64
	minExt     int64
	maxExt     int64

	audioStarted bool
	firstTS      uint32
	audio        []byte

	digits      []byte
	eventSeen   bool
	lastEventTS uint32
}

// NewStream returns a stream for ssrc. dtmfPT is the telephone-event
// payload type (-1 if none); at most maxBytes of audio are kept.
func NewStream(ssrc uint32, dtmfPT, maxBytes int) *Stream {
	return &Stream{SSRC: ssrc, AudioPT: -1, dtmfPT: dtmfPT, maxBytes: maxBytes}
}

// Add records one packet of the stream. a pays for audio growth.
func (s *Stream) Add(h Header, payload []byte, a Allowance) {
	s.Packets++
	s.trackSeq(h.Seq)

	if s.dtmfPT >= 0 && int(h.PayloadType) == s.dtmfPT {
		s.addEvent(h, payload)
		return
	}
	if s.AudioPT < 0 {
		s.AudioPT = int(h.PayloadType)
	}
	if int(h.PayloadType) != s.AudioPT || (s.AudioPT != PCMU && s.AudioPT != PCMA) {
		// comfort noise or a codec we did not answer with: counted, not recorded
		return
	}
	if !s.audioStarted {
		s.audioStarted, s.firstTS = true, h.Timestamp
	}
	// G.711 is one byte per sample, so the timestamp offset is the byte offset
	off := int64(int32(h.Timestamp - s.firstTS))
	if off < 0 {
		// older than the first audio packet (reordered): nowhere to put it
		return
	}
	end := off + int64(len(payload))
	if end > int64(s.maxBytes) {
		s.Truncated = true
		return
	}
	if grow := int(end) - len(s.audio); grow > 0 {
		if !a.Take(grow) {
			s.Truncated = true
			return
		}
		silence := Silence(s.AudioPT)
		for range grow {
			s.audio = append(s.audio, silence)
		}
	}
	copy(s.audio[off:end], payload)
}

// trackSeq extends the 16-bit sequence number so loss survives wraparound.
func (s *Stream) trackSeq(seq uint16) {
	if !s.seqStarted {
		s.seqStarted = true
		s.lastExt, s.minExt, s.maxExt = int64(seq), int64(seq), int64(seq)
		return
	}
	ext := s.lastExt + int64(int16(seq-uint16(s.lastExt)))
	s.lastExt = ext
	s.minExt = min(s.minExt, ext)
	s.maxExt = max(s.maxExt, ext)
}

// addEvent keeps one digit per event: all packets of an event (including the
// repeated end packets) share its RTP timestamp.
func (s *Stream) addEvent(h Header, payload []byte) {
	ev, err := ParseEvent(payload)
	if err != nil {
		return
	}
	if s.eventSeen && h.Timestamp == s.lastEventTS {
		return
	}
	s.eventSeen, s.lastEventTS = true, h.Timestamp
	digit := ev.Digit()
	if digit == "" {
		return
	}
	if len(s.digits) >= maxDigits {
		s.Truncated = true
		return
	}
	s.digits = append(s.digits, digit...)
}

// Lost is the number of packets missing from the sequence number range.
func (s *Stream) Lost() int {
	if !s.seqStarted {
		return 0
	}
	return max(0, int(s.maxExt-s.minExt+1)-s.Packets)
}

// DTMF returns the digits in the order they were pressed.
func (s *Stream) DTMF() string {
	return string(s.digits)
}

// Audio returns the recorded G.711 samples.
func (s *Stream) Audio() []byte {
	return s.audio
}

// DurationMs is the length of the recorded audio.
func (s *Stream) DurationMs() int {
	return len(s.audio) * 1000 / SampleRate
}

// Silence is the G.711 code of a zero sample.
func Silence(pt int) byte {
	if pt == PCMA {
		return 0xd5
	}
	return 0xff
}

// WAV wraps G.711 samples (8 kHz mono) in a RIFF/WAVE file: format tag 7 for
// µ-law (PCMU), 6 for A-law (PCMA), with the fact chunk non-PCM formats need.
func WAV(pt int, samples []byte) []byte {
	format := uint16(7)
	if pt == PCMA {
		format = 6
	}
	const fmtLen, factLen = 18, 4
	size := 4 + (8 + fmtLen) + (8 + factLen) + (8 + len(samples))
	out := make([]byte, 0, 8+size+1)
	le := binary.LittleEndian
	out = append(out, "RIFF"...)
	out = le.AppendUint32(out, uint32(size+len(samples)%2))
	out = append(out, "WAVE"...)
	out = append(out, "fmt "...)
	out = le.AppendUint32(out, fmtLen)
	out = le.AppendUint16(out, format)
	out = le.AppendUint16(out, 1)          // channels
	out = le.AppendUint32(out, SampleRate) // sample rate
	out = le.AppendUint32(out, SampleRate) // byte rate
	out = le.AppendUint16(out, 1)          // block align
	out = le.AppendUint16(out, 8)          // bits per sample
	out = le.AppendUint16(out, 0)          // extension size
	out = append(out, "fact"...)
	out = le.AppendUint32(out, factLen)
	out = le.AppendUint32(out, uint32(len(samples)))
	out = append(out, "data"...)
	out = le.AppendUint32(out, uint32(len(samples)))
	out = append(out, samples...)
	if len(samples)%2 == 1 {
		out = append(out, 0) // chunks are word aligned
	}
	return out
}
