package udp

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/producer"
	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/udp/itp"
)

const (
	maxITPPayload = 1024
	// itpStreamTimeout mirrors the Raven II MASTER_CONN_TIMEOUT: a master
	// silent for this long starts a new stream.
	itpStreamTimeout = 5 * time.Second
	maxITPStreams    = 1024
)

// itpNow is the stream clock; tests replace it.
var itpNow = time.Now

type parsedITP struct {
	Direction      string  `json:"direction,omitempty"`
	Command        string  `json:"command,omitempty"`
	Status         string  `json:"status,omitempty"`
	Layout         string  `json:"layout,omitempty"`
	Sequence       uint32  `json:"sequence,omitempty"`
	LastSequence   uint32  `json:"last_sequence,omitempty"`
	SequenceStatus string  `json:"sequence_status,omitempty"`
	PacTyp         uint32  `json:"pactyp,omitempty"`
	Version        uint32  `json:"version,omitempty"`
	SurgeonMode    int32   `json:"surgeon_mode,omitempty"`
	Checksum       int32   `json:"checksum,omitempty"`
	ChecksumOK     *bool   `json:"checksum_ok,omitempty"`
	ButtonState    []int32 `json:"button_state,omitempty"`
	Grasp          []int32 `json:"grasp,omitempty"`
	Packets        int     `json:"packets,omitempty"`
	Runlevel       string  `json:"runlevel,omitempty"`
	Payload        []byte  `json:"payload,omitempty"`
	Truncated      bool    `json:"truncated,omitempty"`
}

type itpStream struct {
	last     uint32
	seen     bool
	seq      uint32 // slave's own v_struct sequence
	packets  int
	lastSeen time.Time
}

type itpStreams struct {
	mu      sync.Mutex
	streams map[string]*itpStream
}

var itpState = &itpStreams{streams: map[string]*itpStream{}}

// next classifies seq for the master at key and returns the sequence class,
// the slave's next reply sequence and the stream's packet count. A stream
// expires after itpStreamTimeout; when the table is full the oldest goes.
func (s *itpStreams) next(key string, seq uint32, now time.Time) (string, uint32, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.streams[key]
	if ok && now.Sub(st.lastSeen) >= itpStreamTimeout {
		ok = false
	}
	if !ok {
		if len(s.streams) >= maxITPStreams {
			s.evict(now)
		}
		st = &itpStream{}
		s.streams[key] = st
	}
	st.lastSeen = now
	st.packets++
	var status string
	status, st.last = itp.Classify(st.last, st.seen, seq)
	if status != itp.SeqReflect {
		st.seen = true
	}
	st.seq++
	return status, st.seq, st.packets
}

func (s *itpStreams) evict(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, st := range s.streams {
		if now.Sub(st.lastSeen) >= itpStreamTimeout {
			delete(s.streams, k)
			continue
		}
		if oldestKey == "" || st.lastSeen.Before(oldest) {
			oldestKey, oldest = k, st.lastSeen
		}
	}
	if len(s.streams) >= maxITPStreams {
		delete(s.streams, oldestKey)
	}
}

// HandleITP parses an ITP u_struct from a telesurgery master and answers as a
// Raven II-style slave robot: a v_struct status (PEDAL_DN while the surgeon is
// engaged), or the datagram reflected back for sequence 0. Sequence numbers
// are tracked per master address and port. Replies are never larger than the
// request.
func HandleITP(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	payload := make([]byte, min(len(data), maxITPPayload))
	copy(payload, data[:len(payload)])

	events := []parsedITP{}
	endReason := connection.EndHandlerClose
	defer func() {
		md.EndReason = endReason
		if err := h.ProduceUDP("itp", srcAddr, dstAddr, md, helpers.FirstOrEmpty[parsedITP](events).Payload, events); err != nil {
			logger.Error("Failed to produce message", slog.String("protocol", "itp"), producer.ErrAttr(err))
		}
	}()

	frame := parsedITP{
		Direction: "read",
		Command:   "UNKNOWN",
		Payload:   payload,
		Truncated: len(data) > maxITPPayload,
	}
	u, err := itp.Parse(data)
	if err != nil {
		events = append(events, frame)
		logger.Debug("Failed to parse ITP datagram", slog.String("protocol", "itp"), producer.ErrAttr(err), slog.Int("bytes", len(data)))
		return nil
	}
	status, replySeq, packets := itpState.next(srcAddr.String(), u.Sequence, itpNow())
	frame.Command = "u_struct"
	frame.Layout = u.Layout
	frame.Sequence = u.Sequence
	frame.SequenceStatus = status
	frame.PacTyp = u.PacTyp
	frame.Version = u.Version
	frame.SurgeonMode = u.SurgeonMode
	frame.Checksum = u.Checksum
	checksumOK := u.Checksum == u.ExpectedChecksum()
	frame.ChecksumOK = &checksumOK
	frame.ButtonState = u.ButtonState[:]
	frame.Grasp = u.Grasp[:]
	frame.Packets = packets
	events = append(events, frame)

	logger.Info("ITP packet received",
		slog.String("handler", "itp"),
		slog.String("protocol", "itp"),
		slog.String("src_ip", srcAddr.IP.String()),
		slog.Int("src_port", srcAddr.Port),
		slog.Int("dest_port", dstAddr.Port),
		slog.String("layout", u.Layout),
		slog.String("sequence_status", status),
	)

	var resp []byte
	write := parsedITP{Direction: "write"}
	if status == itp.SeqReflect {
		resp = payload
		write.Command, write.Status = "reflect", "reflect"
	} else {
		v := itp.BuildReply(u, replySeq)
		resp = v.Marshal()
		write.Command = "v_struct"
		write.Status = itp.RunlevelName(v.Runlevel)
		write.Runlevel = write.Status
		write.Sequence = v.Sequence
		write.LastSequence = v.LastSequence
		write.PacTyp = v.PacTyp
		write.Version = v.Version
		write.Checksum = v.Checksum
	}
	write.Payload = resp
	events = append(events, write)
	if err := h.ReplyUDP(srcAddr, dstAddr, resp); err != nil {
		logger.Error("Failed to send ITP reply", slog.String("protocol", "itp"), producer.ErrAttr(err))
		endReason = connection.EndWriteError
	}
	return nil
}
