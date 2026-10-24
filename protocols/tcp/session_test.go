package tcp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/stretchr/testify/require"
)

func newTestTracker(table *sessionTable[parsedHTTP], hp *fakeHoneypot, src string) *sessionTracker[parsedHTTP] {
	return &sessionTracker[parsedHTTP]{
		srcHost: src,
		table:   table,
		spec: sessionSpec[parsedHTTP]{
			protocol:      "http",
			payload:       httpPayload,
			stamp:         stampHTTP,
			size:          func(f parsedHTTP) int { return len(f.Payload) },
			groupBySource: true,
		},
		md:     connection.Metadata{EndReason: connection.EndClientClose},
		remote: staticAddr{src + ":1234"},
		h:      hp,
		logger: &recordingLogger{},
	}
}

func producedHTTPFrames(t *testing.T, hp *fakeHoneypot) ([]parsedHTTP, string) {
	t.Helper()
	p := waitProduced(t, hp)
	return p.decoded.([]parsedHTTP), p.endReason
}

func TestSessionRollsOverMidConnectionAtFrameLimit(t *testing.T) {
	withHTTPSessionIdle(t, time.Minute)
	hp := newFakeHoneypot()
	tr := newTestTracker(newSessionTable[parsedHTTP](), hp, "198.51.100.1")
	tr.bind("cookie")
	first := tr.session

	for i := 0; i < maxSessionFrames+1; i++ {
		tr.record(parsedHTTP{Direction: "read"})
	}
	require.NotSame(t, first, tr.session)
	require.Equal(t, "cookie", tr.session.id, "the new session keeps the client's id")

	// the full session is produced as soon as no connection holds it
	events, _ := producedHTTPFrames(t, hp)
	require.Len(t, events, maxSessionFrames)
	tr.session.endNow()
	events, _ = producedHTTPFrames(t, hp)
	require.Len(t, events, 1)
}

func TestSessionRollsOverAtByteLimit(t *testing.T) {
	withHTTPSessionIdle(t, time.Minute)
	hp := newFakeHoneypot()
	tr := newTestTracker(newSessionTable[parsedHTTP](), hp, "198.51.100.2")
	tr.ensure()
	first := tr.session

	chunk := bytes.Repeat([]byte("x"), 1<<20)
	for i := 0; i < maxSessionBytes>>20; i++ {
		tr.record(parsedHTTP{Direction: "read", Payload: chunk})
	}
	require.Same(t, first, tr.session)
	tr.record(parsedHTTP{Direction: "read", Payload: []byte("next")})
	require.NotSame(t, first, tr.session)

	events, _ := producedHTTPFrames(t, hp)
	require.Len(t, events, maxSessionBytes>>20)
	tr.session.endNow()
	waitProduced(t, hp)
}

func TestSessionTableEvictsIdlestWhenFull(t *testing.T) {
	withHTTPSessionIdle(t, time.Minute)
	hp := newFakeHoneypot()
	table := newSessionTable[parsedHTTP]()
	table.limit = 2

	older := newTestTracker(table, hp, "198.51.100.3")
	older.ensure()
	older.record(parsedHTTP{Direction: "read", Payload: []byte("older")})
	older.closeAndProduce(nil)
	newer := newTestTracker(table, hp, "198.51.100.4")
	newer.ensure()
	newer.closeAndProduce(nil)

	third := newTestTracker(table, hp, "198.51.100.5")
	third.ensure()
	require.NotNil(t, third.session)

	events, endReason := producedHTTPFrames(t, hp)
	require.Equal(t, connection.EndEvicted, endReason)
	require.Equal(t, []byte("older"), events[0].Payload)
	require.Len(t, table.sessions, 2)

	third.session.endNow()
}

func TestSessionTableFullOfBusySessionsKeepsFramesLocal(t *testing.T) {
	withHTTPSessionIdle(t, time.Minute)
	hp := newFakeHoneypot()
	table := newSessionTable[parsedHTTP]()
	table.limit = 1

	busy := newTestTracker(table, hp, "198.51.100.6")
	busy.ensure()
	require.NotNil(t, busy.session)

	local := newTestTracker(table, hp, "198.51.100.7")
	local.ensure()
	require.Nil(t, local.session)
	require.NotEmpty(t, local.sessionID, "a session id is still handed out")
	id := local.sessionID
	local.ensure()
	require.Equal(t, id, local.sessionID, "the id stays stable across requests")
	local.record(parsedHTTP{Direction: "read", Payload: []byte("solo")})

	client, server := net.Pipe()
	defer client.Close()
	local.closeAndProduce(server)
	events, _ := producedHTTPFrames(t, hp)
	require.Len(t, events, 1)
	require.Equal(t, []byte("solo"), events[0].Payload)
	require.Equal(t, id, events[0].SessionID)

	busy.session.endNow()
}

func TestSessionIdleFinishSkipsAcquiredSession(t *testing.T) {
	withHTTPSessionIdle(t, time.Minute)
	hp := newFakeHoneypot()
	tr := newTestTracker(newSessionTable[parsedHTTP](), hp, "198.51.100.8")
	tr.ensure()
	tr.record(parsedHTTP{Direction: "read"})

	// a timer or eviction that lost the race to an acquire must not produce
	tr.session.finish(true, connection.EndEvicted)
	require.True(t, tr.session.joinable())
	select {
	case <-hp.produced:
		t.Fatal("produced a session that a connection still holds")
	default:
	}
	tr.session.endNow()
	waitProduced(t, hp)
}
