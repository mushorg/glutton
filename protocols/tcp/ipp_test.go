package tcp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/tcp/ipp"
	"github.com/stretchr/testify/require"
)

// Synthetic IPP requests in the RFC 8010 encoding; no captured traffic yet.
// Operations follow what ipphoney (gitlab.com/bontchev/ipphoney) logs.
var ippGetPrinterAttrs = []byte("\x02\x00\x00\x0b\x00\x00\x00\x01\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x02enE\x00\x0bprinter-uri\x004ipp://203.0.113.5:631/printers/HP_LaserJet_Pro_M404nD\x00\x14requested-attributes\x00\x0cprinter-nameD\x00\x00\x00\x16printer-make-and-model\x03")

var ippPrintJob = []byte("\x02\x00\x00\x02\x00\x00\x00\x02\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x02enE\x00\x0bprinter-uri\x004ipp://203.0.113.5:631/printers/HP_LaserJet_Pro_M404nB\x00\x14requesting-user-name\x00\x04rootB\x00\x08job-name\x00\x04testI\x00\x0fdocument-format\x00\x16application/postscript\x03%!PS\x0ashowpage\x0a")

var ippPrintURI = []byte("\x02\x00\x00\x03\x00\x00\x00\x03\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x02enE\x00\x0bprinter-uri\x004ipp://203.0.113.5:631/printers/HP_LaserJet_Pro_M404nE\x00\x0cdocument-uri\x00\x18http://198.51.100.7/a.ps\x03")

var ippAddModifyPrinter = []byte("\x02\x00@\x03\x00\x00\x00\x04\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x02enE\x00\x0bprinter-uri\x00#ipp://203.0.113.5:631/printers/evil\x04E\x00\x0adevice-uri\x00\x0dfile:///tmp/xB\x00\x08ppd-name\x00\x03raw\x03*PPD-Adobe: \x224.3\x22\x0a")

var ippDate = time.Date(2026, 10, 24, 9, 30, 5, 0, time.UTC)

const ippHost = "203.0.113.5:631"

func ippPost(path string, body []byte, extra ...string) []byte {
	head := "POST " + path + " HTTP/1.1\r\nHost: " + ippHost + "\r\nContent-Type: application/ipp\r\n" +
		"User-Agent: CUPS/2.4.7 (Linux 6.8.0; x86_64) IPP/2.0\r\n"
	for _, h := range extra {
		head += h + "\r\n"
	}
	return append([]byte(head+"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"), body...)
}

func startIPP(t *testing.T) (net.Conn, *bufio.Reader, *fakeHoneypot, chan error, *[][]byte) {
	t.Helper()
	stored := &[][]byte{}
	prev := storeIPP
	storeIPP = func(data []byte) (string, error) {
		*stored = append(*stored, append([]byte(nil), data...))
		return "hash", nil
	}
	ippJobs.Store(0)
	t.Cleanup(func() {
		storeIPP = prev
		ippJobs.Store(0)
	})

	client, serverConn := net.Pipe()
	t.Cleanup(func() { client.Close() })
	hp := newFakeHoneypot()
	server := newIPPServer(serverConn)
	server.now = func() time.Time { return ippDate }
	done := make(chan error, 1)
	go func() {
		done <- handleIPP(context.Background(), server, connection.Metadata{TargetPort: 631}, &recordingLogger{}, hp)
	}()
	require.NoError(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	return client, bufio.NewReader(client), hp, done, stored
}

// readIPPReply reads one HTTP response (head plus Content-Length body).
func readIPPReply(t *testing.T, r *bufio.Reader) []byte {
	t.Helper()
	var out []byte
	clen := 0
	for {
		line, err := r.ReadString('\n')
		require.NoError(t, err)
		out = append(out, line...)
		if v, ok := strings.CutPrefix(line, "Content-Length: "); ok {
			clen, _ = strconv.Atoi(strings.TrimSpace(v))
		}
		if line == "\r\n" {
			break
		}
	}
	body := make([]byte, clen)
	_, err := io.ReadFull(r, body)
	require.NoError(t, err)
	return append(out, body...)
}

// ippBody returns the IPP message of an HTTP response.
func ippBody(t *testing.T, reply []byte) ipp.Message {
	t.Helper()
	_, body, ok := bytes.Cut(reply, []byte("\r\n\r\n"))
	require.True(t, ok)
	m, err := ipp.Parse(body)
	require.NoError(t, err)
	return m
}

func waitIPP(t *testing.T, hp *fakeHoneypot, done chan error) (producedTCP, error) {
	t.Helper()
	var err error
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish")
	}
	produced := <-hp.produced
	require.Empty(t, hp.produced, "exactly one event per session")
	require.Equal(t, "ipp", produced.protocol)
	return produced, err
}

func expectedIPPReply(status uint16, reqID uint32, message string, groups ...ipp.Group) []byte {
	resp := ipp.Response{Major: 2, Minor: 0, Status: status, RequestID: reqID,
		Groups: append([]ipp.Group{ipp.OperationGroup(message)}, groups...)}
	return ipp.HTTPResponse(ipp.DefaultPersona, http.StatusOK, "application/ipp", resp.Encode(), ippDate, true)
}

func TestHandleIPPGetPrinterAttributes(t *testing.T) {
	client, r, hp, done, stored := startIPP(t)
	req := ippPost("/printers/HP_LaserJet_Pro_M404n", ippGetPrinterAttrs)
	_, err := client.Write(req)
	require.NoError(t, err)
	reply := readIPPReply(t, r)
	require.Equal(t, expectedIPPReply(ipp.StatusOK, 1, "", ipp.Group{Tag: ipp.TagPrinter, Attrs: []ipp.Attr{
		ipp.Text("printer-make-and-model", "HP LaserJet Pro M404n, driverless, cups-filters 1.28.15"),
		ipp.Name("printer-name", "HP_LaserJet_Pro_M404n"),
	}}), reply)
	require.Contains(t, string(reply), "Server: CUPS/2.4 IPP/2.1\r\n")

	require.NoError(t, client.Close())
	produced, err := waitIPP(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, *stored)
	require.Equal(t, connection.EndClientClose, produced.endReason)
	require.Equal(t, req, produced.payload)
	m, _ := ipp.Parse(ippGetPrinterAttrs)
	require.Equal(t, []parsedIPP{
		{
			Direction:  "read",
			Command:    "Get-Printer-Attributes",
			Method:     "POST",
			Path:       "/printers/HP_LaserJet_Pro_M404n",
			Version:    "2.0",
			RequestID:  1,
			UserAgent:  "CUPS/2.4.7 (Linux 6.8.0; x86_64) IPP/2.0",
			PrinterURI: "ipp://203.0.113.5:631/printers/HP_LaserJet_Pro_M404n",
			Attributes: m.Attributes,
			Payload:    req,
		},
		{Direction: "write", Status: "200", IPPStatus: "successful-ok", RequestID: 1, Payload: reply},
	}, produced.decoded)
}

func TestHandleIPPGetPrinterAttributesAll(t *testing.T) {
	client, r, hp, done, _ := startIPP(t)
	// CUPS-Get-Printers without requested-attributes returns the whole queue
	body := []byte("\x02\x00\x40\x02\x00\x00\x00\x05\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x02en\x03")
	_, err := client.Write(ippPost("/", body))
	require.NoError(t, err)
	m := ippBody(t, readIPPReply(t, r))
	require.Equal(t, ipp.StatusOK, m.Operation) // status in the operation slot
	require.Equal(t, "ipp://"+ippHost+"/printers/HP_LaserJet_Pro_M404n", m.Get("printer", "printer-uri-supported"))
	require.Equal(t, "3", m.Get("printer", "printer-state"))
	require.Equal(t, []string{"1.0", "1.1", "2.0", "2.1"}, m.Values("printer", "ipp-versions-supported"))
	require.Equal(t, "true", m.Get("printer", "printer-is-shared"))
	require.NoError(t, client.Close())
	produced, err := waitIPP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, "CUPS-Get-Printers", produced.decoded.([]parsedIPP)[0].Command)
}

func TestHandleIPPPrintJobChunkedContinue(t *testing.T) {
	client, r, hp, done, stored := startIPP(t)
	// CUPS clients announce documents with Expect: 100-continue and chunk them
	head := []byte("POST /printers/HP_LaserJet_Pro_M404n HTTP/1.1\r\nHost: " + ippHost + "\r\n" +
		"Content-Type: application/ipp\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n")
	body := []byte(fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(ippPrintJob), ippPrintJob))
	_, err := client.Write(head)
	require.NoError(t, err)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "HTTP/1.1 100 Continue\r\n", line)
	line, err = r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "\r\n", line)
	_, err = client.Write(body)
	require.NoError(t, err)
	reply := readIPPReply(t, r)
	require.Equal(t, expectedIPPReply(ipp.StatusOK, 2, "", ipp.Group{Tag: ipp.TagJob,
		Attrs: ipp.JobAttributes(ipp.DefaultPersona, ippHost, 1, ipp.JobProcessing, "job-printing")}), reply)

	// the job can be looked up afterwards; an unknown one cannot
	getJob := func(reqID byte, jobID byte) []byte {
		return append([]byte{2, 0, 0, 0x09, 0, 0, 0, reqID, 0x01},
			append([]byte("!\x00\x06job-id\x00\x04\x00\x00\x00"), jobID, 0x03)...)
	}
	_, err = client.Write(ippPost("/jobs/1", getJob(3, 1)))
	require.NoError(t, err)
	m := ippBody(t, readIPPReply(t, r))
	require.Equal(t, "9", m.Get("job", "job-state"))
	_, err = client.Write(ippPost("/jobs/7", getJob(4, 7)))
	require.NoError(t, err)
	m = ippBody(t, readIPPReply(t, r))
	require.Equal(t, ipp.StatusNotFound, m.Operation)
	require.Equal(t, "Job #7 does not exist.", m.Get("operation", "status-message"))

	require.NoError(t, client.Close())
	produced, err := waitIPP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("%!PS\nshowpage\n")}, *stored)
	frames := produced.decoded.([]parsedIPP)
	require.Len(t, frames, 8)
	require.Equal(t, parsedIPP{Direction: "read", Command: "POST", Method: "POST", Path: "/printers/HP_LaserJet_Pro_M404n", Payload: head}, frames[0])
	require.Equal(t, parsedIPP{Direction: "write", Status: "100", Payload: ipp.Continue()}, frames[1])
	m, _ = ipp.Parse(ippPrintJob)
	require.Equal(t, parsedIPP{
		Direction:      "read",
		Command:        "Print-Job",
		Method:         "POST",
		Path:           "/printers/HP_LaserJet_Pro_M404n",
		Version:        "2.0",
		RequestID:      2,
		RequestingUser: "root",
		PrinterURI:     "ipp://203.0.113.5:631/printers/HP_LaserJet_Pro_M404n",
		JobName:        "test",
		DocumentFormat: "application/postscript",
		Attributes:     m.Attributes,
		PayloadHash:    "hash",
		Payload:        body,
	}, frames[2])
	require.Equal(t, parsedIPP{Direction: "write", Status: "200", IPPStatus: "successful-ok", RequestID: 2, JobID: 1, Payload: reply}, frames[3])
	require.Equal(t, int32(1), frames[4].JobID)
	require.Equal(t, "client-error-not-found", frames[7].IPPStatus)
}

func TestHandleIPPPrintURINotFetched(t *testing.T) {
	client, r, hp, done, stored := startIPP(t)
	_, err := client.Write(ippPost("/printers/HP_LaserJet_Pro_M404n", ippPrintURI, "Connection: close"))
	require.NoError(t, err)
	reply := readIPPReply(t, r)
	require.Contains(t, string(reply), "Connection: close\r\n")
	m := ippBody(t, reply)
	require.Equal(t, "1", m.Get("job", "job-id"))

	// Connection: close ends the session without the client closing
	produced, err := waitIPP(t, hp, done)
	require.NoError(t, err)
	require.Empty(t, *stored)
	require.Equal(t, connection.EndHandlerClose, produced.endReason)
	frames := produced.decoded.([]parsedIPP)
	require.Len(t, frames, 2)
	require.Equal(t, "Print-URI", frames[0].Command)
	require.Equal(t, "http://198.51.100.7/a.ps", frames[0].DocumentURI)
}

func TestHandleIPPAdminBasicAuth(t *testing.T) {
	client, r, hp, done, stored := startIPP(t)
	// CVE-2024-47177 style queue creation: refused until credentials arrive
	_, err := client.Write(ippPost("/admin/", ippAddModifyPrinter))
	require.NoError(t, err)
	unauth := readIPPReply(t, r)
	require.Equal(t, ipp.Unauthorized(ipp.DefaultPersona, ippDate, true), unauth)
	require.Contains(t, string(unauth), "HTTP/1.1 401 Unauthorized\r\n")
	require.Contains(t, string(unauth), "WWW-Authenticate: Basic realm=\"CUPS\"\r\n")

	authed := ippPost("/admin/", ippAddModifyPrinter, "Authorization: Basic cm9vdDp0b29y") // root:toor
	_, err = client.Write(authed)
	require.NoError(t, err)
	ok := readIPPReply(t, r)
	require.Equal(t, expectedIPPReply(ipp.StatusOK, 4, ""), ok)

	require.NoError(t, client.Close())
	produced, err := waitIPP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("*PPD-Adobe: \"4.3\"\n"), []byte("*PPD-Adobe: \"4.3\"\n")}, *stored)
	frames := produced.decoded.([]parsedIPP)
	require.Len(t, frames, 4)
	require.Equal(t, "CUPS-Add-Modify-Printer", frames[0].Command)
	require.Equal(t, "file:///tmp/x", frames[0].DeviceURI)
	require.Equal(t, "raw", frames[0].PPDName)
	require.Empty(t, frames[0].Password)
	require.Equal(t, parsedIPP{Direction: "write", Status: "401", RequestID: 4, Payload: unauth}, frames[1])
	require.Equal(t, "root", frames[2].Username)
	require.Equal(t, "toor", frames[2].Password)
	require.Equal(t, parsedIPP{Direction: "write", Status: "200", IPPStatus: "successful-ok", RequestID: 4, Payload: ok}, frames[3])
}

func TestHandleIPPWebInterface(t *testing.T) {
	client, r, hp, done, _ := startIPP(t)
	get := []byte("GET / HTTP/1.1\r\nHost: " + ippHost + "\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\n\r\n")
	_, err := client.Write(get)
	require.NoError(t, err)
	home := readIPPReply(t, r)
	_, want := ipp.WebPage(ipp.DefaultPersona, "/", ippDate, true)
	require.Equal(t, want, home)
	require.Contains(t, string(home), "<title>Home - CUPS 2.4.1</title>")

	_, err = client.Write([]byte("GET /nope HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)
	require.Contains(t, string(readIPPReply(t, r)), "HTTP/1.1 404 Not Found\r\n")

	_, err = client.Write([]byte("PUT /admin/conf/cupsd.conf HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nLog\n"))
	require.NoError(t, err)
	require.Contains(t, string(readIPPReply(t, r)), "HTTP/1.1 401 Unauthorized\r\n")

	// HEAD gets the GET headers without a body
	_, err = client.Write([]byte("HEAD /printers/ HTTP/1.1\r\nHost: x\r\n\r\n"))
	require.NoError(t, err)
	head, err := r.ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "HTTP/1.1 200 OK\r\n", head)
	for line := ""; line != "\r\n"; {
		line, err = r.ReadString('\n')
		require.NoError(t, err)
	}

	require.NoError(t, client.Close())
	produced, err := waitIPP(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedIPP)
	require.Len(t, frames, 8)
	require.Equal(t, parsedIPP{Direction: "read", Command: "GET", Method: "GET", Path: "/", UserAgent: "Mozilla/5.0 zgrab/0.x", Payload: get}, frames[0])
	require.Equal(t, parsedIPP{Direction: "write", Status: "200", Payload: home}, frames[1])
	require.Equal(t, "404", frames[3].Status)
	require.Equal(t, "/admin/conf/cupsd.conf", frames[4].Path)
	require.Equal(t, "401", frames[5].Status)
	require.Equal(t, "HEAD", frames[6].Command)
}

func TestHandleIPPMalformed(t *testing.T) {
	t.Run("bad IPP body keeps the session", func(t *testing.T) {
		client, r, hp, done, _ := startIPP(t)
		_, err := client.Write(ippPost("/", []byte{2, 0, 0, 0x0b, 0, 0, 0, 9, 0x01, 0x47}))
		require.NoError(t, err)
		require.Contains(t, string(readIPPReply(t, r)), "HTTP/1.1 400 Bad Request\r\n")
		require.NoError(t, client.Close())
		produced, err := waitIPP(t, hp, done)
		require.NoError(t, err)
		frames := produced.decoded.([]parsedIPP)
		require.Len(t, frames, 2)
		require.Equal(t, "Get-Printer-Attributes", frames[0].Command)
		require.Equal(t, uint32(9), frames[0].RequestID)
		require.Equal(t, parsedIPP{Direction: "write", Status: "400", RequestID: 9, Payload: frames[1].Payload}, frames[1])
	})

	t.Run("bad request line", func(t *testing.T) {
		client, r, hp, done, _ := startIPP(t)
		_, err := client.Write([]byte("GARBAGE\r\n"))
		require.NoError(t, err)
		require.Contains(t, string(readIPPReply(t, r)), "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n")
		produced, err := waitIPP(t, hp, done)
		require.ErrorIs(t, err, ipp.ErrMalformed)
		require.Equal(t, connection.EndReadError, produced.endReason)
		frames := produced.decoded.([]parsedIPP)
		require.Equal(t, parsedIPP{Direction: "read", Payload: []byte("GARBAGE\r\n")}, frames[0])
		require.Equal(t, "400", frames[1].Status)
	})

	t.Run("unsupported version and operation", func(t *testing.T) {
		client, r, hp, done, _ := startIPP(t)
		_, err := client.Write(ippPost("/", []byte{9, 9, 0, 0x0b, 0, 0, 0, 1, 0x03}))
		require.NoError(t, err)
		require.Equal(t, ipp.StatusVersionNotSupported, ippBody(t, readIPPReply(t, r)).Operation)
		_, err = client.Write(ippPost("/", []byte{2, 0, 0x7f, 0x01, 0, 0, 0, 2, 0x03}))
		require.NoError(t, err)
		m := ippBody(t, readIPPReply(t, r))
		require.Equal(t, ipp.StatusOperationNotSupported, m.Operation)
		require.NoError(t, client.Close())
		produced, err := waitIPP(t, hp, done)
		require.NoError(t, err)
		frames := produced.decoded.([]parsedIPP)
		require.Equal(t, "9.9", frames[0].Version)
		require.Equal(t, "server-error-version-not-supported", frames[1].IPPStatus)
		require.Equal(t, "0x7F01", frames[2].Command)
	})
}

func TestHandleIPPEarlyDisconnect(t *testing.T) {
	client, _, hp, done, _ := startIPP(t)
	partial := ippPost("/", ippGetPrinterAttrs)[:120]
	_, err := client.Write(partial)
	require.NoError(t, err)
	require.NoError(t, client.Close())
	produced, err := waitIPP(t, hp, done)
	require.NoError(t, err)
	require.Equal(t, []parsedIPP{{Direction: "read", Payload: partial}}, produced.decoded)
	require.Equal(t, partial, produced.payload)

	// a body cut short still records the head and what arrived
	client, _, hp, done, _ = startIPP(t)
	req := ippPost("/", ippGetPrinterAttrs)
	partial = req[:len(req)-20]
	_, err = client.Write(partial)
	require.NoError(t, err)
	require.NoError(t, client.Close())
	produced, err = waitIPP(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedIPP)
	require.Len(t, frames, 1)
	require.Equal(t, "POST", frames[0].Command)
	require.Equal(t, partial, frames[0].Payload)
}

func TestHandleIPPOversizeDocument(t *testing.T) {
	client, r, hp, done, stored := startIPP(t)
	doc := bytes.Repeat([]byte("A"), ippMaxBody)
	body := append(append([]byte(nil), ippPrintJob...), doc...)
	req := ippPost("/", body)
	go func() { _, _ = client.Write(req) }()
	reply := readIPPReply(t, r)
	require.Equal(t, "1", ippBody(t, reply).Get("job", "job-id"))
	require.NoError(t, client.Close())
	produced, err := waitIPP(t, hp, done)
	require.NoError(t, err)
	frames := produced.decoded.([]parsedIPP)
	require.True(t, frames[0].Truncated)
	require.Equal(t, "Print-Job", frames[0].Command)
	head := len(req) - len(body)
	require.Len(t, frames[0].Payload, head+ippMaxBody, "payload is capped at ippMaxBody")
	require.Len(t, *stored, 1)
	require.Len(t, (*stored)[0], ippMaxBody-len(ippPrintJob)+len("%!PS\nshowpage\n"))
}
