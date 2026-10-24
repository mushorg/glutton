package ipp

import (
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Persona is the CUPS server and shared queue the honeypot presents.
type Persona struct {
	Server       string // HTTP Server header
	Version      string // CUPS version in web page titles
	PrinterName  string
	PrinterInfo  string
	MakeAndModel string
	Location     string
	UUID         string
}

// DefaultPersona is a stock Ubuntu 22.04 CUPS sharing a driverless laser printer.
var DefaultPersona = Persona{
	Server:       "CUPS/2.4 IPP/2.1",
	Version:      "2.4.1",
	PrinterName:  "HP_LaserJet_Pro_M404n",
	PrinterInfo:  "HP LaserJet Pro M404n",
	MakeAndModel: "HP LaserJet Pro M404n, driverless, cups-filters 1.28.15",
	Location:     "",
	UUID:         "urn:uuid:4e2a7c1b-9d3f-3c1e-6a5b-2f8d0e7c4a91",
}

// operationsSupported are the operations CUPS advertises for a queue.
var operationsSupported = []int32{
	int32(OpPrintJob), int32(OpValidateJob), int32(OpCreateJob), int32(OpSendDocument),
	int32(OpCancelJob), int32(OpGetJobAttributes), int32(OpGetJobs), int32(OpGetPrinterAttributes),
	int32(OpHoldJob), int32(OpReleaseJob), int32(OpRestartJob), int32(OpPausePrinter),
	int32(OpResumePrinter), int32(OpPurgeJobs), int32(OpSetJobAttributes), int32(OpEnablePrinter),
	int32(OpDisablePrinter), int32(OpCancelJobs), int32(OpCancelMyJobs), int32(OpCloseJob),
	int32(OpIdentifyPrinter), int32(OpValidateDocument), int32(OpCUPSAcceptJobs),
	int32(OpCUPSRejectJobs), int32(OpCUPSMoveJob), int32(OpCUPSAuthenticateJob), int32(OpCUPSGetPPD),
}

// Job states (RFC 8011 §5.3.7).
const (
	JobPending    int32 = 3
	JobProcessing int32 = 5
	JobCompleted  int32 = 9
)

// URIHost returns the authority to put in printer and job URIs: the
// client's Host header when it is a plain host[:port], with CUPS' default
// port added; otherwise "localhost:631".
func URIHost(hostHeader string) string {
	h := strings.TrimSpace(hostHeader)
	if h == "" || len(h) > 255 || strings.ContainsFunc(h, func(r rune) bool {
		return !(r == '.' || r == '-' || r == ':' || r == '[' || r == ']' ||
			r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}) {
		return "localhost:631"
	}
	if _, _, err := net.SplitHostPort(h); err != nil {
		return net.JoinHostPort(strings.Trim(h, "[]"), "631")
	}
	return h
}

// PrinterURI is the queue's ipp:// URI.
func (p Persona) PrinterURI(host string) string {
	return "ipp://" + host + "/printers/" + p.PrinterName
}

// JobURI is a job's ipp:// URI.
func (p Persona) JobURI(host string, jobID int32) string {
	return "ipp://" + host + "/jobs/" + strconv.Itoa(int(jobID))
}

// OperationGroup is the operation-attributes group every response starts
// with, plus a status-message when message is set.
func OperationGroup(message string) Group {
	g := Group{Tag: TagOperation, Attrs: []Attr{
		Charset("attributes-charset", "utf-8"),
		Language("attributes-natural-language", "en"),
	}}
	if message != "" {
		g.Attrs = append(g.Attrs, Text("status-message", message))
	}
	return g
}

// PrinterAttributes returns the queue's attributes, filtered by the
// request's requested-attributes (all when empty or a group keyword).
func PrinterAttributes(p Persona, host string, now time.Time, requested []string) []Attr {
	uri := p.PrinterURI(host)
	all := []Attr{
		Charset("charset-configured", "utf-8"),
		Charset("charset-supported", "us-ascii", "utf-8"),
		Boolean("color-supported", false),
		Keyword("compression-supported", "none", "gzip"),
		Integer("copies-default", 1),
		Range("copies-supported", 1, 9999),
		MimeType("document-format-default", "application/octet-stream"),
		MimeType("document-format-supported", "application/octet-stream", "application/pdf",
			"application/postscript", "application/vnd.cups-raster", "image/jpeg", "image/png",
			"image/pwg-raster", "image/urf", "text/plain"),
		Language("generated-natural-language-supported", "en"),
		Keyword("ipp-features-supported", "ipp-everywhere"),
		Keyword("ipp-versions-supported", "1.0", "1.1", "2.0", "2.1"),
		Name("job-sheets-default", "none", "none"),
		Keyword("media-default", "iso_a4_210x297mm"),
		Keyword("media-supported", "iso_a4_210x297mm", "iso_a5_148x210mm", "na_letter_8.5x11in",
			"na_legal_8.5x14in", "iso_b5_176x250mm", "na_executive_7.25x10.5in"),
		Boolean("multiple-document-jobs-supported", true),
		Integer("multiple-operation-time-out", 900),
		Language("natural-language-configured", "en"),
		Enum("operations-supported", operationsSupported...),
		Keyword("pdl-override-supported", "attempted"),
		DateTime("printer-current-time", now),
		Text("printer-info", p.PrinterInfo),
		Boolean("printer-is-accepting-jobs", true),
		Boolean("printer-is-shared", true),
		Text("printer-location", p.Location),
		Text("printer-make-and-model", p.MakeAndModel),
		URI("printer-more-info", "http://"+host+"/printers/"+p.PrinterName),
		Name("printer-name", p.PrinterName),
		Resolution("printer-resolution-default", 600, 600),
		Enum("printer-state", 3),
		Text("printer-state-message", ""),
		Keyword("printer-state-reasons", "none"),
		Integer("printer-up-time", int32(now.Unix())),
		URI("printer-uri-supported", uri),
		URI("printer-uuid", p.UUID),
		Integer("queued-job-count", 0),
		Keyword("sides-default", "one-sided"),
		Keyword("sides-supported", "one-sided", "two-sided-long-edge", "two-sided-short-edge"),
		Keyword("uri-authentication-supported", "none"),
		Keyword("uri-security-supported", "none"),
	}
	if len(requested) == 0 || slices.ContainsFunc(requested, func(r string) bool {
		return r == "all" || r == "printer-description" || r == "job-template"
	}) {
		return all
	}
	var out []Attr
	for _, a := range all {
		if slices.Contains(requested, a.Name) {
			out = append(out, a)
		}
	}
	return out
}

// JobAttributes describes one job of the queue.
func JobAttributes(p Persona, host string, jobID, state int32, reasons string) []Attr {
	return []Attr{
		Integer("job-id", jobID),
		URI("job-uri", p.JobURI(host, jobID)),
		URI("job-printer-uri", p.PrinterURI(host)),
		Enum("job-state", state),
		Keyword("job-state-reasons", reasons),
	}
}

// httpDate formats now like CUPS' Date header.
func httpDate(now time.Time) string {
	return now.UTC().Format(http.TimeFormat)
}

// HTTPResponse builds a CUPS-style HTTP/1.1 response. extra holds
// additional "Name: value" header lines.
func HTTPResponse(p Persona, code int, contentType string, body []byte, now time.Time, keepAlive bool, extra ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	if keepAlive {
		b.WriteString("Connection: Keep-Alive\r\n")
	} else {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("Content-Language: en\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	if contentType != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	}
	fmt.Fprintf(&b, "Date: %s\r\n", httpDate(now))
	if keepAlive {
		b.WriteString("Keep-Alive: timeout=30\r\n")
	}
	fmt.Fprintf(&b, "Server: %s\r\n", p.Server)
	for _, h := range extra {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("X-Frame-Options: DENY\r\n")
	b.WriteString("Content-Security-Policy: frame-ancestors 'none'\r\n")
	b.WriteString("\r\n")
	return append([]byte(b.String()), body...)
}

// Continue is the interim response to Expect: 100-continue.
func Continue() []byte {
	return []byte("HTTP/1.1 100 Continue\r\n\r\n")
}

// Unauthorized asks for Basic credentials the way cupsd does for admin operations.
func Unauthorized(p Persona, now time.Time, keepAlive bool) []byte {
	return HTTPResponse(p, http.StatusUnauthorized, "text/html; charset=utf-8", nil, now, keepAlive,
		`WWW-Authenticate: Basic realm="CUPS"`)
}

// WebPage answers a browser request for path with CUPS' web interface.
func WebPage(p Persona, path string, now time.Time, keepAlive bool) (int, []byte) {
	var title, content string
	code := http.StatusOK
	switch strings.TrimSuffix(path, "/") {
	case "":
		title = "Home"
		content = `<h1>CUPS ` + p.Version + `</h1>
<p>CUPS is the standards-based, open source printing system developed by Apple Inc. for macOS&reg; and other UNIX&reg;-like operating systems.</p>`
	case "/printers":
		title = "Printers"
		content = `<table class="list" summary="Printer List">
<thead><tr><th>Queue Name</th><th>Description</th><th>Location</th><th>Make and Model</th><th>Status</th></tr></thead>
<tbody><tr><td><a href="/printers/` + p.PrinterName + `">` + p.PrinterName + `</a></td><td>` + p.PrinterInfo +
			`</td><td>` + p.Location + `</td><td>` + p.MakeAndModel + `</td><td>Idle</td></tr></tbody>
</table>`
	case "/printers/" + p.PrinterName:
		title = p.PrinterName
		content = `<h2 class="title"><a href="/printers/` + p.PrinterName + `">` + p.PrinterName + `</a> (Idle, Accepting Jobs, Shared)</h2>
<table summary="` + p.PrinterName + `"><tr><th>Description:</th><td>` + p.PrinterInfo + `</td></tr>
<tr><th>Driver:</th><td>` + p.MakeAndModel + ` (grayscale, 2-sided printing)</td></tr></table>`
	default:
		code = http.StatusNotFound
		title = "Not Found"
		content = `<h1>Not Found</h1>
<p>The requested resource was not found on this server.</p>`
	}
	body := []byte(`<!DOCTYPE HTML>
<html>
  <head>
    <link rel="stylesheet" href="/cups.css" type="text/css">
    <link rel="shortcut icon" href="/apple-touch-icon.png" type="image/png">
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=9">
    <meta name="viewport" content="width=device-width">
    <title>` + title + ` - CUPS ` + p.Version + `</title>
  </head>
  <body>
    <div class="header">
      <ul>
        <li><a href="/">Home</a></li>
        <li><a href="/admin">Administration</a></li>
        <li><a href="/classes/">Classes</a></li>
        <li><a href="/help/">Help</a></li>
        <li><a href="/jobs/">Jobs</a></li>
        <li><a href="/printers/">Printers</a></li>
      </ul>
    </div>
    <div class="body">
      <div class="row">
` + content + `
      </div>
    </div>
    <div class="footer">Copyright &copy; 2021-2022 OpenPrinting. All rights reserved.</div>
  </body>
</html>
`)
	return code, HTTPResponse(p, code, "text/html; charset=utf-8", body, now, keepAlive)
}

// adminOperations need an authenticated user under cupsd's default policy.
var adminOperations = map[uint16]bool{
	OpPausePrinter: true, OpResumePrinter: true, OpPurgeJobs: true, OpSetPrinterAttributes: true,
	OpEnablePrinter: true, OpDisablePrinter: true, 0x0024: true, 0x0025: true, 0x0026: true,
	0x0027: true, 0x0028: true, 0x0029: true, 0x002A: true, 0x002B: true, OpCancelJobs: true,
	OpCUPSAddModifyPrinter: true, OpCUPSDeletePrinter: true, OpCUPSAddModifyClass: true,
	OpCUPSDeleteClass: true, OpCUPSAcceptJobs: true, OpCUPSRejectJobs: true, OpCUPSSetDefault: true,
	OpCUPSGetDevices: true, OpCUPSMoveJob: true,
}

// RequiresAuth reports whether cupsd answers op with 401 until the client
// sends credentials.
func RequiresAuth(op uint16) bool {
	return adminOperations[op]
}
