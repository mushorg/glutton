package udp

import (
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/udp/rtp"
	"github.com/spf13/viper"

	"github.com/ghettovoice/gosip/sip"
)

const (
	// maxRTPStreams caps the SSRCs recorded per call.
	maxRTPStreams = 4
	// maxRTPCallBytes caps the audio kept per call: 120 s of G.711.
	maxRTPCallBytes = 120 * rtp.SampleRate
	// maxRTPCallPackets is how many media packets keep a dialog alive (two
	// streams for 120 s at 20 ms per packet); after it the dialog ends
	// conn_timeout after the last datagram that re-armed it.
	maxRTPCallPackets = 12000
	// maxRTPTotalBytes caps the audio held across all open calls.
	maxRTPTotalBytes = 64 << 20
)

// sipRecordMedia reports whether answered calls bind their SDP port and
// record the caller's RTP (config key sip.record_media, default true).
func sipRecordMedia() bool {
	if viper.IsSet("sip.record_media") {
		return viper.GetBool("sip.record_media")
	}
	return true
}

// sipStoreRecording saves a WAV file and returns its SHA-256; tests swap it
// to keep files out of the working directory.
var sipStoreRecording = func(data []byte) (string, error) {
	return helpers.Store(data, filepath.Join("payloads", "rtp"))
}

// sipMediaBytes is the audio held by all open recordings.
var sipMediaBytes atomic.Int64

// sipMediaTable maps (caller IP, honeypot media port) to the dialog whose
// SDP answer offered that port. Each dialog binds at most two caller IPs,
// so the table is bounded by the dialog table.
type sipMediaTable struct {
	mu       sync.Mutex
	bindings map[string]*sipDialog
}

var sipMedia = &sipMediaTable{bindings: map[string]*sipDialog{}}

func sipMediaKey(ip net.IP, port int) string {
	return ip.String() + "|" + strconv.Itoa(port)
}

func (t *sipMediaTable) bind(d *sipDialog, keys []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		t.bindings[k] = d
	}
}

func (t *sipMediaTable) unbind(d *sipDialog, keys []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		if t.bindings[k] == d {
			delete(t.bindings, k)
		}
	}
}

func (t *sipMediaTable) lookup(ip net.IP, port int) *sipDialog {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bindings[sipMediaKey(ip, port)]
}

// handleSIPMedia hands an RTP datagram to the answered call whose SDP port
// it was sent to. It reports false when no call claims it.
func handleSIPMedia(srcAddr, dstAddr *net.UDPAddr, data []byte) bool {
	d := sipMedia.lookup(srcAddr.IP, dstAddr.Port)
	return d != nil && d.handleMedia(srcAddr, data)
}

// sipRecording is the caller media of one call.
type sipRecording struct {
	names   map[uint8]string // payload type names from our SDP answer
	dtmfPT  int
	keys    []string
	streams map[uint32]*rtp.Stream
	order   []uint32
	packets int
	// dropped counts packets of SSRCs beyond maxRTPStreams
	dropped int
	used    int
}

// Take charges audio growth to the call and to the global budget.
func (r *sipRecording) Take(n int) bool {
	if r.used+n > maxRTPCallBytes {
		return false
	}
	if sipMediaBytes.Add(int64(n)) > maxRTPTotalBytes {
		sipMediaBytes.Add(-int64(n))
		return false
	}
	r.used += n
	return true
}

func (r *sipRecording) release() {
	sipMediaBytes.Add(-int64(r.used))
	r.used = 0
}

// bindMediaLocked starts (or, after a re-INVITE, moves) the recording when
// the dialog sends a 2xx with SDP: RTP from the caller's signaling IP, or
// the c= address of its offer, to our m=audio port is routed to the dialog.
func (d *sipDialog) bindMediaLocked(final sip.Response) {
	if !sipRecordMedia() || !final.IsSuccess() || d.invite == nil {
		return
	}
	answer, ok := rtp.ParseSDPAudio(final.Body())
	if !ok {
		return
	}
	ips := []net.IP{d.src.IP}
	if offer, ok := rtp.ParseSDPAudio(d.invite.Body()); ok && offer.IP != nil &&
		!offer.IP.IsUnspecified() && !offer.IP.Equal(d.src.IP) {
		ips = append(ips, offer.IP)
	}
	keys := make([]string, 0, len(ips))
	for _, ip := range ips {
		keys = append(keys, sipMediaKey(ip, answer.Port))
	}
	if d.rec == nil {
		d.rec = &sipRecording{streams: map[uint32]*rtp.Stream{}}
	} else {
		sipMedia.unbind(d, d.rec.keys)
	}
	d.rec.names, d.rec.dtmfPT, d.rec.keys = answer.Names, answer.DTMF(), keys
	sipMedia.bind(d, keys)
}

// handleMedia records one RTP packet of the call. Datagrams that are not
// RTP are left to the generic handler.
func (d *sipDialog) handleMedia(src *net.UDPAddr, data []byte) bool {
	h, payload, err := rtp.Parse(data)
	if err != nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.produced || d.rec == nil {
		return false
	}
	rec := d.rec
	d.seen = d.table.clock.Add(1)
	rec.packets++
	s := rec.streams[h.SSRC]
	if s == nil {
		if len(rec.streams) >= maxRTPStreams {
			rec.dropped++
			return true
		}
		s = rtp.NewStream(h.SSRC, rec.dtmfPT, maxRTPCallBytes)
		rec.streams[h.SSRC] = s
		rec.order = append(rec.order, h.SSRC)
		d.logger.Info("SIP call media received",
			slog.String("protocol", "sip"),
			slog.String("src_ip", src.IP.String()),
			slog.Int("src_port", src.Port),
			slog.String("ssrc", fmt.Sprintf("%08x", h.SSRC)),
		)
	}
	s.Add(h, payload, rec)
	// media keeps the call open, up to the packet cap
	if rec.packets <= maxRTPCallPackets {
		d.armIdleLocked()
	}
	return true
}

// mediaFrames ends the recording and returns one summary frame per stream,
// storing each stream's audio as a WAV file.
func (d *sipDialog) mediaFrames(rec *sipRecording, callID string) []parsedSIP {
	sipMedia.unbind(d, rec.keys)
	defer rec.release()
	frames := make([]parsedSIP, 0, len(rec.order))
	for i, ssrc := range rec.order {
		s := rec.streams[ssrc]
		frame := parsedSIP{
			Direction:  "read",
			Command:    "rtp",
			CallID:     callID,
			SSRC:       fmt.Sprintf("%08x", ssrc),
			Packets:    s.Packets,
			Lost:       s.Lost(),
			DurationMs: s.DurationMs(),
			DTMF:       s.DTMF(),
			Truncated:  s.Truncated || (i == len(rec.order)-1 && rec.dropped > 0),
		}
		if s.AudioPT >= 0 {
			frame.Codec = rec.names[uint8(s.AudioPT)]
			if frame.Codec == "" {
				frame.Codec = "pt" + strconv.Itoa(s.AudioPT)
			}
		}
		if audio := s.Audio(); len(audio) > 0 {
			hash, err := sipStoreRecording(rtp.WAV(s.AudioPT, audio))
			if err != nil {
				d.logger.Error("Failed to store SIP call recording", slog.String("protocol", "sip"), producer.ErrAttr(err))
			}
			frame.PayloadHash = hash
		}
		frames = append(frames, frame)
	}
	return frames
}
