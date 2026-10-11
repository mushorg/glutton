package smb

// Variant selects whether TRANS2 SESSION_SETUP is answered as a clean host or
// as one already carrying the DoublePulsar implant.
type Variant int

const (
	// Clean answers TRANS2 SESSION_SETUP with the usual error.
	Clean Variant = iota
	// Infected emulates the DoublePulsar implant (ping, exec and kill).
	Infected
)

// Variants is the rotation order for returning sources; Clean comes first, so a
// first visit sees the baseline and roughly one in three visits looks infected.
var Variants = []Variant{Clean, Clean, Infected}

func (v Variant) String() string {
	if v == Infected {
		return "infected"
	}
	return "clean"
}
