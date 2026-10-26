package sip

import (
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/protocols/interfaces"
	"github.com/mushorg/glutton/protocols/recall"
	"github.com/spf13/viper"
)

const (
	// recallKey is the recall protocol key shared by SIP over UDP, TCP and
	// TLS, so a source's visit spans all three.
	recallKey = "sip"
	// UnackedCounter counts, per visit in the recall store, the answered
	// INVITEs whose final response (200, 183+200, 401, 486) the source never
	// ACKed. Dial testers that only read the status code stall there; the
	// next call in the same visit gets the next variant instead of the same
	// outcome until recall.visit_gap passes.
	UnackedCounter = "unacked"
	// SilentUnacked is how many unACKed final responses in one visit make a
	// source silent: a dialer that ignored that many gets each later final
	// response once, without the RFC 3261 resends. The captured dial-prefix
	// testers (User-Agent zxcvfdf11, pplsip) never ACK, so the resends were
	// about a dozen datagrams per call to a peer that does not read them.
	SilentUnacked = 3
	// inviteCounter counts the new INVITE calls of a visit for RejectInvite.
	inviteCounter = "invite"
	// DefaultRejectInvites is how many new INVITE calls in a source's first
	// visit get 404 before calls are answered (config key
	// sip.reject_invites). Toll-fraud tools stop at the first prefix that
	// rings, so a few failures make them reveal more of their dial-prefix
	// list. Only the first visit rejects: a scanner that sends one INVITE
	// per visit would otherwise get 404 every time and never see a call
	// ring, be challenged or be busied by the later variants. The count
	// lives in the recall store, so it starts over once the source is
	// forgotten (recall.ttl or eviction).
	DefaultRejectInvites = 2
)

// RejectLimit overrides sip.reject_invites in tests when >= 0.
var RejectLimit = -1

// RejectInvites returns how many INVITE calls a first visit rejects.
func RejectInvites() int {
	if RejectLimit >= 0 {
		return RejectLimit
	}
	if viper.IsSet("sip.reject_invites") {
		return viper.GetInt("sip.reject_invites")
	}
	return DefaultRejectInvites
}

// Visit is the response variant picked for a source's current visit. A
// zero Number means no visit (unparsable datagram, or no request yet).
// Store is the store the visit began in, so a call finishing later notes
// it there.
type Visit struct {
	Number  int
	Variant Variant
	Store   *recall.Store
}

// BeginVisit marks activity from ip and returns its visit. A source that
// returns after recall.visit_gap gets the next Variants entry, and within a
// visit each final response the source left unACKed moves it one further
// (see Escalate).
func BeginVisit(store *recall.Store, ip net.IP, logger interfaces.Logger) Visit {
	v := store.Begin(recallKey, ip, len(Variants))
	visit := Visit{Number: v.Number, Variant: Variants[v.Variant], Store: store}
	// a source that ignored a final response in this visit gets the next one
	visit.Variant = Escalate(visit.Variant, store.Counter(recallKey, ip, UnackedCounter))
	if v.Started && v.Number > 1 {
		logger.Info("returning SIP source",
			slog.String("protocol", "sip"),
			slog.String("src_ip", ip.String()),
			slog.Int("visit", v.Number),
			slog.String("variant", visit.Variant.String()),
			slog.String("previous_variant", v.Previous.Variant),
			slog.Any("previous_commands", v.Previous.Commands),
		)
	}
	return visit
}

// RejectInvite counts a new INVITE call in the source's first visit and
// reports whether it is among the first RejectInvites of that visit. Later
// visits and sources without a visit (recall disabled) are never rejected.
func (v Visit) RejectInvite(ip net.IP) bool {
	limit := RejectInvites()
	if limit <= 0 || v.Store == nil || v.Number != 1 {
		return false
	}
	n := v.Store.Count(recallKey, ip, inviteCounter)
	return n > 0 && n <= limit
}

// NoteUnacked counts a final response (status code) the source never
// ACKed towards escalating its variant, logs it and reports whether it
// counted. The deliberate 404 rejections and the 487 after the caller's own
// CANCEL do not count.
func (v Visit) NoteUnacked(ip net.IP, code int, logger interfaces.Logger) bool {
	if v.Number == 0 || v.Store == nil || code == 404 || code == 487 {
		return false
	}
	n := v.Store.Count(recallKey, ip, UnackedCounter)
	logger.Info("SIP final response not ACKed",
		slog.String("protocol", "sip"),
		slog.String("src_ip", ip.String()),
		slog.Int("status", code),
		slog.String("variant", v.Variant.String()),
		slog.String("next_variant", Escalate(v.Variant, 1).String()),
		slog.Int("unacked", n),
	)
	return true
}

// Silent reports whether the source has left SilentUnacked or more final
// responses unACKed in this visit, so resending them is pointless. It is
// false without a visit or a store (recall disabled).
func (v Visit) Silent(ip net.IP) bool {
	if v.Number == 0 || v.Store == nil {
		return false
	}
	return v.Store.Counter(recallKey, ip, UnackedCounter) >= SilentUnacked
}

// VisitRead is the part of a read frame a visit remembers.
type VisitRead struct {
	Command, Path, Username, UserAgent string
}

// Note stores what the source did in one event: its read frames.
func (v Visit) Note(ip net.IP, reads []VisitRead) {
	if v.Number == 0 || v.Store == nil {
		return
	}
	v.Store.Note(recallKey, ip, func(s *recall.Summary) {
		s.Variant = v.Variant.String()
		s.Events++
		for _, r := range reads {
			s.AddCommand(r.Command)
			s.AddPath(r.Path)
			s.AddUsername(r.Username)
			if r.UserAgent != "" {
				s.UserAgent = r.UserAgent
			}
		}
	})
}

// RegisterChallengeSet overrides sip.register_challenge in tests when non-nil.
var RegisterChallengeSet *bool

// RegisterChallenge reports whether an unauthenticated REGISTER is answered
// with a 401 digest challenge in every variant (config key
// sip.register_challenge, default off). Any credentials are then accepted, so
// a REGISTER-only scanner reveals the username and digest it guesses with and
// still reaches the INVITE stage.
func RegisterChallenge() bool {
	if RegisterChallengeSet != nil {
		return *RegisterChallengeSet
	}
	return viper.GetBool("sip.register_challenge")
}

// ExtensionsSet overrides sip.extensions in tests when non-nil.
var ExtensionsSet *string

// extensions returns the sip.extensions entries: single extensions ("200",
// "admin") and numeric ranges ("100-120"), comma or space separated. Empty
// means the leak is off.
func extensions() []string {
	var raw []string
	if ExtensionsSet != nil {
		raw = []string{*ExtensionsSet}
	} else {
		raw = viper.GetStringSlice("sip.extensions")
	}
	var out []string
	for _, r := range raw {
		out = append(out, strings.FieldsFunc(r, func(c rune) bool { return c == ',' || c == ' ' })...)
	}
	return out
}

// KnownExtension reports whether user is one of the sip.extensions entries.
// It is true for every user when sip.extensions is empty (the default), so
// REGISTER and OPTIONS answer every extension alike, as chan_pjsip's
// artificial endpoint does.
func KnownExtension(user string) bool {
	entries := extensions()
	if len(entries) == 0 {
		return true
	}
	n, numErr := strconv.ParseUint(user, 10, 64)
	for _, e := range entries {
		if lo, hi, ok := strings.Cut(e, "-"); ok {
			l, errLo := strconv.ParseUint(lo, 10, 64)
			h, errHi := strconv.ParseUint(hi, 10, 64)
			if errLo == nil && errHi == nil {
				// a range matches numbers only, not its own spelling
				if numErr == nil && l <= n && n <= h {
					return true
				}
				continue
			}
		}
		if e == user {
			return true
		}
	}
	return false
}
