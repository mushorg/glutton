package tcp

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/helpers"
)

// echoLoaderLines splits data into Mirai echo-loader lines in the shape seen
// in Ochi event bedf4355-6886-489c-b2f6-69df475a314c: 32 bytes per line,
// `> F` for the first chunk and `>> F` after it.
func echoLoaderLines(data []byte, file string) []string {
	var lines []string
	for off := 0; off < len(data); off += 32 {
		var b strings.Builder
		for _, c := range data[off:min(off+32, len(data))] {
			fmt.Fprintf(&b, "\\x%02X", c)
		}
		redir := ">>"
		if off == 0 {
			redir = ">"
		}
		lines = append(lines, fmt.Sprintf("/bin/busybox echo -ne \"%s\" %s %s\r\n", b.String(), redir, file))
	}
	return lines
}

// fakeELF is a synthetic stand-in for a Mirai dlr stub: an ELF32 header
// followed by filler, n bytes long. seed varies the content per architecture.
func fakeELF(n int, seed byte) []byte {
	out := []byte{0x7f, 'E', 'L', 'F', 1, 1, 1, 0}
	for len(out) < n {
		out = append(out, byte(len(out))^seed)
	}
	return out[:n]
}

type recordedStore struct {
	mu   sync.Mutex
	data [][]byte
}

func swapTelnetStore(t *testing.T) *recordedStore {
	t.Helper()
	rec := &recordedStore{}
	orig := telnetStoreSample
	telnetStoreSample = func(data []byte, folder string) (string, error) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		require.Equal(t, "samples", folder)
		rec.data = append(rec.data, append([]byte(nil), data...))
		return helpers.SHA256Hex(data), nil
	}
	t.Cleanup(func() { telnetStoreSample = orig })
	return rec
}

func TestParseTelnetEcho(t *testing.T) {
	for _, tc := range []struct {
		line string
		want telnetEchoWrite
		ok   bool
	}{
		{`/bin/busybox echo -ne "\x7F\x45\x4C\x46" > .d` + "\r\n", telnetEchoWrite{file: ".d", data: []byte("\x7fELF")}, true},
		{`/bin/busybox echo -ne "\x01\x00" >> .d`, telnetEchoWrite{file: ".d", data: []byte{1, 0}, append: true}, true},
		// stray word before the redirection is an extra echo argument
		{`/bin/busybox echo -ne "\x20\x66\x69\x0A"  ar >> .k`, telnetEchoWrite{file: ".k", data: []byte(" fi\n ar"), append: true}, true},
		{`echo -e 'a\x41\0102' > ./x`, telnetEchoWrite{file: "x", data: []byte("aAB\n")}, true},
		{`echo -en "ab\cZZ" > y`, telnetEchoWrite{file: "y", data: []byte("ab")}, true},
		// the shell turns \\ into \ inside double quotes, then echo decodes \x41
		{`echo -ne "\\x41\q" > z`, telnetEchoWrite{file: "z", data: []byte(`A\q`)}, true},
		{`/bin/busybox echo > /tmp/.b && sh /tmp/.b && cd /tmp/`, telnetEchoWrite{}, false},
		{`echo hello > f`, telnetEchoWrite{}, false},            // no -e: not a loader line
		{`echo -ne "\x41" | sh`, telnetEchoWrite{}, false},      // pipe
		{`echo -ne "\x41" > a; sh a`, telnetEchoWrite{}, false}, // chained
		{`echo -ne "$(id)" > a`, telnetEchoWrite{}, false},      // substitution
		{`echo -ne "\x41" >`, telnetEchoWrite{}, false},
		{`cat .d > .e`, telnetEchoWrite{}, false},
	} {
		got, ok := parseTelnetEcho(tc.line)
		require.Equal(t, tc.ok, ok, tc.line)
		require.Equal(t, tc.want, got, tc.line)
	}
}

func TestTelnetRunTargets(t *testing.T) {
	require.Equal(t, []string{".d", ".d", "dvrHelper"}, telnetRunTargets("/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep\r\n"))
	require.Equal(t, []string{".k"}, telnetRunTargets("sh .k\r\n"))
	require.Equal(t, []string{"a", "/tmp/b"}, telnetRunTargets("chmod 777 a && /tmp/b"))
	require.Empty(t, telnetRunTargets("enable\r\n"))
}

// echoServer is a telnetServer without a connection, for driving
// handleEchoLine the way runShellLine does.
func echoServer() *telnetServer {
	return &telnetServer{files: map[string]*telnetFile{}, storedHashes: map[string]bool{}, echoFrame: -1}
}

func (s *telnetServer) feedEcho(line string) {
	s.events = append(s.events, parsedTelnet{Direction: "read", Message: line})
	if !s.handleEchoLine(line) {
		s.events = append(s.events, parsedTelnet{Direction: "write", Message: telnetPrompt})
	}
}

func TestHandleEchoLineTruncateAndAppend(t *testing.T) {
	s := echoServer()
	s.feedEcho(`echo -ne "\x41" > f` + "\r\n")
	s.feedEcho(`echo -ne "\x42" >> f` + "\r\n")
	require.Equal(t, []byte("AB"), s.files["f"].data)
	s.feedEcho(`echo -ne "\x43" > f` + "\r\n")  // truncates, new frame
	s.feedEcho(`echo -ne "\x44" >> g` + "\r\n") // other file, new frame
	require.Equal(t, []byte("C"), s.files["f"].data)
	require.Equal(t, []byte("D"), s.files["g"].data)
	require.Equal(t, 2, s.fileBytes)
	require.Equal(t, []parsedTelnet{
		{Direction: "read", Path: "f", Lines: 2, Message: `echo -ne "\x41" > f` + "\r\n" + `echo -ne "\x42" >> f` + "\r\n"},
		{Direction: "write", Message: telnetPrompt},
		{Direction: "read", Path: "f", Lines: 1, Message: `echo -ne "\x43" > f` + "\r\n"},
		{Direction: "write", Message: telnetPrompt},
		{Direction: "read", Path: "g", Lines: 1, Message: `echo -ne "\x44" >> g` + "\r\n"},
		{Direction: "write", Message: telnetPrompt},
	}, s.events)
}

func TestHandleEchoLineCaps(t *testing.T) {
	// one line of 16 KiB of data stays under maxTelnetLine (4 bytes per \xHH)
	chunk := strings.Repeat(`\x41`, 16<<10)
	line := func(redir, file string) string { return `echo -ne "` + chunk + `" ` + redir + " " + file + "\r\n" }

	s := echoServer()
	s.feedEcho(line(">", "big"))
	for range maxTelnetEchoFile/(16<<10) + 4 {
		s.feedEcho(line(">>", "big"))
	}
	require.Len(t, s.files["big"].data, maxTelnetEchoFile)
	require.True(t, s.files["big"].truncated)
	// merged frames stay under maxTelnetEchoFrame, and the capped one is flagged
	var truncated bool
	for _, ev := range s.events {
		require.LessOrEqual(t, len(ev.Message), maxTelnetEchoFrame)
		truncated = truncated || ev.Truncated
	}
	require.True(t, truncated)

	// the per-connection total caps the sum over files
	for i := range maxTelnetEchoTotal / maxTelnetEchoFile {
		s.feedEcho(line(">", fmt.Sprintf("f%d", i)))
		for range maxTelnetEchoFile / (16 << 10) {
			s.feedEcho(line(">>", fmt.Sprintf("f%d", i)))
		}
	}
	require.Equal(t, maxTelnetEchoTotal, s.fileBytes)
	total := 0
	for _, f := range s.files {
		total += len(f.data)
	}
	require.Equal(t, maxTelnetEchoTotal, total)
}

func TestHandleTelnetEchoLoaderStoresFiles(t *testing.T) {
	rec := swapTelnetStore(t)
	arm := fakeELF(1160, 0x28) // size of the captured arm dlr stub
	mips := fakeELF(2000, 0x08)

	client, reader, hp, _, done := startTelnetFrom(t, staticAddr{"177.85.57.42:11861"}, telnetArches[0].greeting)
	armLines := echoLoaderLines(arm, ".d")
	for _, l := range armLines {
		telnetSend(t, client, l)
		telnetExpect(t, client, reader, "> ") // every line is still answered on the wire
	}
	run := "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep\r\n"
	telnetSend(t, client, run)
	telnetExpect(t, client, reader, "> ")
	// next architecture overwrites .d and is never run
	mipsLines := echoLoaderLines(mips, ".d")
	for _, l := range mipsLines {
		telnetSend(t, client, l)
		telnetExpect(t, client, reader, "> ")
	}
	require.NoError(t, client.Close())
	require.NoError(t, <-done)

	produced := waitProduced(t, hp)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, [][]byte{arm, mips}, rec.data)

	var shell []parsedTelnet
	for _, ev := range produced.decoded.([]parsedTelnet) {
		if ev.Lines > 0 || ev.Command == "/bin/busybox" || (ev.Direction == "write" && ev.Message == "> ") {
			ev.OffsetMs = 0
			shell = append(shell, ev)
		}
	}
	require.Equal(t, []parsedTelnet{
		{Direction: "read", Command: "/bin/busybox", Path: ".d", Lines: len(armLines), Message: strings.Join(armLines, "")},
		{Direction: "write", Message: "> "},
		{Direction: "read", Command: "/bin/busybox", Commands: []string{"/bin/busybox", "./.d", "./dvrHelper"}, Path: ".d",
			Message: run, PayloadHash: helpers.SHA256Hex(arm)},
		{Direction: "write", Message: "> "},
		{Direction: "read", Command: "/bin/busybox", Path: ".d", Lines: len(mipsLines), Message: strings.Join(mipsLines, ""),
			PayloadHash: helpers.SHA256Hex(mips)},
		{Direction: "write", Message: "> "},
	}, shell)
}

func TestHandleTelnetEchoLoaderFitsFrameCap(t *testing.T) {
	rec := swapTelnetStore(t)
	client, serverConn := net.Pipe()
	defer client.Close()
	hp, done := startTelnetDrained(t, newTelnetServer(serverConn), client)

	// eight architectures of ~1.7 KB: 424 echo lines, as in the captured session
	const arches = 8
	lines := 0
	for i := range arches {
		for _, l := range echoLoaderLines(fakeELF(1700, byte(i)), ".d") {
			telnetSend(t, client, l)
			lines++
		}
		telnetSend(t, client, "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep\r\n")
	}
	require.Greater(t, lines, 400)
	require.NoError(t, client.Close())
	waitTelnetDone(t, done)

	produced := waitProduced(t, hp)
	// the drained client may close before the last prompt is written
	require.NotEqual(t, connection.EndMaxFrames, produced.endReason)
	require.Less(t, len(produced.decoded.([]parsedTelnet)), 50)
	require.Len(t, rec.data, arches)
}
