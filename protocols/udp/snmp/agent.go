package snmp

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"time"
)

// Status names for the reply, recorded on the handler's write frame.
const (
	StatusOK         = "ok"
	StatusTooBig     = "too_big"
	StatusNoSuchName = "no_such_name"
	StatusNoAccess   = "no_access"
)

// Agent is a read-only embedded Linux router. It answers the system group
// (1.3.6.1.2.1.1) and nothing else.
type Agent struct {
	descr string
	name  string
	boot  time.Time
	now   func() time.Time
}

var (
	oidSysDescr    = OID{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID = OID{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysUpTime   = OID{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSysContact  = OID{1, 3, 6, 1, 2, 1, 1, 4, 0}
	oidSysName     = OID{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysLocation = OID{1, 3, 6, 1, 2, 1, 1, 6, 0}

	// net-snmp's Linux sysObjectID, matching the Linux sysDescr.
	valSysObjectID = OID{1, 3, 6, 1, 4, 1, 8072, 3, 2, 10}
)

var (
	kernels      = []string{"4.9.152", "4.14.180", "4.19.90", "5.4.124"}
	arches       = []string{"mips", "armv7l", "aarch64"}
	hostPrefixes = []string{"gw", "router", "ap", "edge"}
)

// NewAgent derives a persona from seed: kernel, build date, architecture,
// host name and boot time differ between sensors. now is injectable.
func NewAgent(seed uint64, now func() time.Time) *Agent {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	built := time.Date(2022+r.IntN(3), time.Month(1+r.IntN(12)), 1+r.IntN(28), r.IntN(24), r.IntN(60), r.IntN(60), 0, time.UTC)
	name := fmt.Sprintf("%s-%04x", hostPrefixes[r.IntN(len(hostPrefixes))], r.IntN(0x10000))
	return &Agent{
		descr: fmt.Sprintf("Linux %s %s #1 SMP %s %s", name, kernels[r.IntN(len(kernels))], built.Format("Mon Jan  2 15:04:05 UTC 2006"), arches[r.IntN(len(arches))]),
		name:  name,
		// Booted between 1 hour and 90 days before first use.
		boot: now().Add(-time.Duration(1+r.IntN(90*24)) * time.Hour),
		now:  now,
	}
}

type entry struct {
	oid OID
	val []byte
}

// mib returns the agent's objects in OID order.
func (a *Agent) mib() []entry {
	ticks := uint32(a.now().Sub(a.boot) / (10 * time.Millisecond))
	return []entry{
		{oidSysDescr, tlv(tagOctetString, []byte(a.descr))},
		{oidSysObjectID, encOID(valSysObjectID)},
		{oidSysUpTime, encInt(tagTimeTicks, int64(ticks))},
		{oidSysContact, tlv(tagOctetString, nil)},
		{oidSysName, tlv(tagOctetString, []byte(a.name))},
		{oidSysLocation, tlv(tagOctetString, nil)},
	}
}

func cmpEntry(e entry, t OID) int { return e.oid.compare(t) }

// next returns the first entry strictly after o.
func next(mib []entry, o OID) (entry, bool) {
	i, found := slices.BinarySearchFunc(mib, o, cmpEntry)
	if found {
		i++
	}
	if i < len(mib) {
		return mib[i], true
	}
	return entry{}, false
}

// Respond builds the reply to m, never longer than maxLen bytes (the request
// size). It returns nil when the agent stays silent: an unknown community,
// SNMPv3, a PDU that is not a request, or a reply that cannot fit even as a
// tooBig error.
func (a *Agent) Respond(m *Message, maxLen int) (resp []byte, status string) {
	if m.Version != Version1 && m.Version != Version2c {
		return nil, ""
	}
	if m.Community != Community {
		return nil, ""
	}
	v1 := m.Version == Version1
	mib := a.mib()

	var vbs [][]byte
	errStatus, errIndex := ErrNoError, 0
	status = StatusOK
	switch m.PDUType {
	case PDUGet:
		for i, o := range m.OIDs {
			j, found := slices.BinarySearchFunc(mib, o, cmpEntry)
			switch {
			case found:
				vbs = append(vbs, varbind(o, mib[j].val))
			case v1:
				if errStatus == ErrNoError {
					errStatus, errIndex, status = ErrNoSuchName, i+1, StatusNoSuchName
				}
			default:
				vbs = append(vbs, varbind(o, noSuchObjectValue))
			}
		}
	case PDUGetNext:
		for i, o := range m.OIDs {
			e, ok := next(mib, o)
			switch {
			case ok:
				vbs = append(vbs, varbind(e.oid, e.val))
			case v1:
				if errStatus == ErrNoError {
					errStatus, errIndex, status = ErrNoSuchName, i+1, StatusNoSuchName
				}
			default:
				vbs = append(vbs, varbind(o, endOfMibValue))
			}
		}
	case PDUGetBulk:
		if v1 {
			return nil, ""
		}
		vbs = bulk(mib, m)
	case PDUSet:
		errStatus, errIndex, status = ErrNoAccess, 1, StatusNoAccess
		if v1 {
			errStatus = ErrNoSuchName
			status = StatusNoSuchName
		}
	default:
		return nil, ""
	}
	if errStatus != ErrNoError {
		// Errors echo the request varbinds with NULL values.
		vbs = vbs[:0]
		for _, o := range m.OIDs {
			vbs = append(vbs, varbind(o, nullValue))
		}
	}

	resp = encodeMessage(m.Version, m.Community, m.RequestID, errStatus, errIndex, vbs)
	if m.PDUType == PDUGetBulk {
		// A bulk reply may legitimately carry fewer bindings than asked.
		for len(resp) > maxLen && len(vbs) > 1 {
			vbs = vbs[:len(vbs)-1]
			resp = encodeMessage(m.Version, m.Community, m.RequestID, errStatus, errIndex, vbs)
		}
	}
	if len(resp) <= maxLen {
		return resp, status
	}
	resp = encodeMessage(m.Version, m.Community, m.RequestID, ErrTooBig, 0, nil)
	if len(resp) > maxLen {
		return nil, ""
	}
	return resp, StatusTooBig
}

// bulk implements GetBulk (RFC 3416 §4.2.3). Repetitions are capped.
func bulk(mib []entry, m *Message) [][]byte {
	nonRep := int(max(0, min(m.NonRepeaters, int64(len(m.OIDs)))))
	maxRep := int(max(0, min(m.MaxRepetitions, maxBulkRound)))
	var vbs [][]byte
	step := func(o OID) (OID, bool) {
		e, ok := next(mib, o)
		if !ok {
			vbs = append(vbs, varbind(o, endOfMibValue))
			return o, false
		}
		vbs = append(vbs, varbind(e.oid, e.val))
		return e.oid, true
	}
	for _, o := range m.OIDs[:nonRep] {
		step(o)
	}
	cur := slices.Clone(m.OIDs[nonRep:])
	done := make([]bool, len(cur))
	for r := 0; r < maxRep && len(cur) > 0; r++ {
		allDone := true
		for i := range cur {
			if done[i] {
				vbs = append(vbs, varbind(cur[i], endOfMibValue))
				continue
			}
			o, ok := step(cur[i])
			cur[i] = o
			done[i] = !ok
			allDone = allDone && done[i]
		}
		if allDone {
			break
		}
	}
	return vbs
}
