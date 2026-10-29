package udp

import (
	"net"
	"sync"
	"sync/atomic"
)

func sipDialogKey(src *net.UDPAddr, callID string) string {
	return src.IP.String() + "|" + callID
}

type sipDialogTable struct {
	mu      sync.Mutex
	max     int
	dialogs map[string]*sipDialog
	// clock orders dialogs by last activity for eviction
	clock atomic.Uint64
}

func newSIPDialogTable(max int) *sipDialogTable {
	return &sipDialogTable{max: max, dialogs: map[string]*sipDialog{}}
}

// sipDialogs tracks open UDP SIP dialogs across datagrams.
var sipDialogs = newSIPDialogTable(maxSIPDialogs)

func (t *sipDialogTable) get(key string) *sipDialog {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dialogs[key]
}

// open returns the dialog for key, creating it when absent. A full table
// first evicts its least recently active dialog, which the caller must
// finish.
func (t *sipDialogTable) open(key string, create func() *sipDialog) (d, evicted *sipDialog) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if d := t.dialogs[key]; d != nil {
		return d, nil
	}
	if len(t.dialogs) >= t.max {
		for _, cand := range t.dialogs {
			if evicted == nil || cand.lastSeen() < evicted.lastSeen() {
				evicted = cand
			}
		}
		if evicted != nil {
			delete(t.dialogs, evicted.key)
		}
	}
	d = create()
	t.dialogs[key] = d
	return d, evicted
}

func (t *sipDialogTable) remove(key string, expected *sipDialog) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if current, ok := t.dialogs[key]; ok && current == expected {
		delete(t.dialogs, key)
	}
}
