package ipp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Synthetic requests in the RFC 8010 encoding; no captured traffic yet.
var getPrinterAttrs = []byte("\x02\x00\x00\x0b\x00\x00\x00\x01\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x02enE\x00\x0bprinter-uri\x004ipp://203.0.113.5:631/printers/HP_LaserJet_Pro_M404nD\x00\x14requested-attributes\x00\x0cprinter-nameD\x00\x00\x00\x16printer-make-and-model\x03")

var printJob = []byte("\x02\x00\x00\x02\x00\x00\x00\x02\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x02enE\x00\x0bprinter-uri\x004ipp://203.0.113.5:631/printers/HP_LaserJet_Pro_M404nB\x00\x14requesting-user-name\x00\x04rootB\x00\x08job-name\x00\x04testI\x00\x0fdocument-format\x00\x16application/postscript\x03%!PS\x0ashowpage\x0a")

// attr encodes one attribute for hand-built messages.
func attr(tag byte, name string, value []byte) []byte {
	b := []byte{tag}
	b = binary.BigEndian.AppendUint16(b, uint16(len(name)))
	b = append(b, name...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
	return append(b, value...)
}

func header(op uint16, id uint32) []byte {
	b := []byte{2, 0}
	b = binary.BigEndian.AppendUint16(b, op)
	return binary.BigEndian.AppendUint32(b, id)
}

func TestParseGetPrinterAttributes(t *testing.T) {
	m, err := Parse(getPrinterAttrs)
	require.NoError(t, err)
	require.Equal(t, "2.0", m.Version())
	require.Equal(t, OpGetPrinterAttributes, m.Operation)
	require.Equal(t, "Get-Printer-Attributes", OperationName(m.Operation))
	require.Equal(t, uint32(1), m.RequestID)
	require.Equal(t, []Attribute{
		{Group: "operation", Name: "attributes-charset", Type: "charset", Values: []string{"utf-8"}},
		{Group: "operation", Name: "attributes-natural-language", Type: "naturalLanguage", Values: []string{"en"}},
		{Group: "operation", Name: "printer-uri", Type: "uri", Values: []string{"ipp://203.0.113.5:631/printers/HP_LaserJet_Pro_M404n"}},
		{Group: "operation", Name: "requested-attributes", Type: "keyword", Values: []string{"printer-name", "printer-make-and-model"}},
	}, m.Attributes)
	require.Equal(t, []string{"printer-name", "printer-make-and-model"}, m.Values("operation", "requested-attributes"))
	require.Empty(t, m.Data)
}

func TestParseDocumentData(t *testing.T) {
	m, err := Parse(printJob)
	require.NoError(t, err)
	require.Equal(t, "Print-Job", OperationName(m.Operation))
	require.Equal(t, "root", m.Get("operation", "requesting-user-name"))
	require.Equal(t, "application/postscript", m.Get("operation", "document-format"))
	require.Equal(t, []byte("%!PS\nshowpage\n"), m.Data)
}

func TestParseValueTypes(t *testing.T) {
	b := header(OpCreateJob, 7)
	b = append(b, TagJob)
	b = append(b, attr(TagInteger, "copies", []byte{0, 0, 0, 2})...)
	b = append(b, attr(TagBoolean, "ipp-attribute-fidelity", []byte{1})...)
	b = append(b, attr(TagEnum, "orientation-requested", []byte{0, 0, 0, 4})...)
	b = append(b, attr(TagRange, "page-ranges", []byte{0, 0, 0, 1, 0, 0, 0, 3})...)
	b = append(b, attr(TagResolution, "printer-resolution", []byte{0, 0, 2, 0x58, 0, 0, 2, 0x58, 3})...)
	b = append(b, attr(TagDateTime, "job-hold-until-time", []byte{0x07, 0xea, 10, 24, 9, 30, 5, 0, '+', 0, 0})...)
	b = append(b, attr(TagNameWithLang, "job-name", []byte("\x00\x02en\x00\x05hello"))...)
	b = append(b, attr(TagNoValue, "job-sheets", nil)...)
	b = append(b, attr(TagOctetString, "job-password", []byte{0xff, 0x00})...)
	b = append(b, TagEnd)

	m, err := Parse(b)
	require.NoError(t, err)
	got := map[string]string{}
	for _, a := range m.Attributes {
		require.Equal(t, "job", a.Group)
		got[a.Name] = a.Values[0]
	}
	require.Equal(t, map[string]string{
		"copies":                 "2",
		"ipp-attribute-fidelity": "true",
		"orientation-requested":  "4",
		"page-ranges":            "1-3",
		"printer-resolution":     "600x600dpi",
		"job-hold-until-time":    "2026-10-24T09:30:05.0+00:00",
		"job-name":               "hello",
		"job-sheets":             "no-value",
		"job-password":           "hex:ff00",
	}, got)
}

func TestParseCollections(t *testing.T) {
	// media-col = {media-size = {x-dimension, y-dimension}, media-source}
	// followed by a second media-col value and another attribute
	b := header(OpPrintJob, 1)
	b = append(b, TagJob)
	b = append(b, attr(TagBegCollection, "media-col", nil)...)
	b = append(b, attr(TagMemberName, "", []byte("media-size"))...)
	b = append(b, attr(TagBegCollection, "", nil)...)
	b = append(b, attr(TagMemberName, "", []byte("x-dimension"))...)
	b = append(b, attr(TagInteger, "", []byte{0, 0, 0x52, 0x08})...)
	b = append(b, attr(TagMemberName, "", []byte("y-dimension"))...)
	b = append(b, attr(TagInteger, "", []byte{0, 0, 0x74, 0x04})...)
	b = append(b, attr(TagEndCollection, "", nil)...)
	b = append(b, attr(TagMemberName, "", []byte("media-source"))...)
	b = append(b, attr(TagKeyword, "", []byte("tray-1"))...)
	b = append(b, attr(TagKeyword, "", []byte("tray-2"))...)
	b = append(b, attr(TagEndCollection, "", nil)...)
	b = append(b, attr(TagBegCollection, "", nil)...)
	b = append(b, attr(TagMemberName, "", []byte("media-type"))...)
	b = append(b, attr(TagKeyword, "", []byte("stationery"))...)
	b = append(b, attr(TagEndCollection, "", nil)...)
	b = append(b, attr(TagKeyword, "sides", []byte("one-sided"))...)
	b = append(b, TagEnd)

	m, err := Parse(b)
	require.NoError(t, err)
	require.Equal(t, []Attribute{
		{Group: "job", Name: "media-col", Type: "collection"},
		{Group: "job", Name: "media-col.media-size.x-dimension", Type: "integer", Values: []string{"21000"}},
		{Group: "job", Name: "media-col.media-size.y-dimension", Type: "integer", Values: []string{"29700"}},
		{Group: "job", Name: "media-col.media-source", Type: "keyword", Values: []string{"tray-1", "tray-2"}},
		{Group: "job", Name: "media-col.media-type", Type: "keyword", Values: []string{"stationery"}},
		{Group: "job", Name: "sides", Type: "keyword", Values: []string{"one-sided"}},
	}, m.Attributes)
}

func TestParseCaps(t *testing.T) {
	b := header(OpGetJobs, 1)
	b = append(b, TagOperation)
	for i := 0; i < maxAttributes+5; i++ {
		b = append(b, attr(TagKeyword, "a", []byte("v"))...)
	}
	b = append(b, attr(TagKeyword, "", []byte("dropped"))...)
	b = append(b, TagEnd)
	m, err := Parse(b)
	require.NoError(t, err)
	require.Len(t, m.Attributes, maxAttributes)
	require.True(t, m.Dropped)

	b = header(OpGetJobs, 1)
	b = append(b, TagOperation)
	b = append(b, attr(TagKeyword, "requested-attributes", []byte("all"))...)
	for i := 0; i < maxValues+5; i++ {
		b = append(b, attr(TagKeyword, "", []byte("x"))...)
	}
	b = append(b, TagEnd)
	m, err = Parse(b)
	require.NoError(t, err)
	require.Len(t, m.Attributes[0].Values, maxValues)
	require.True(t, m.Dropped)
}

func TestParseMalformed(t *testing.T) {
	for name, b := range map[string][]byte{
		"short header":           {2, 0, 0, 0x0b},
		"missing end tag":        getPrinterAttrs[:len(getPrinterAttrs)-1],
		"cut value":              getPrinterAttrs[:40],
		"attribute before group": append(header(OpGetJobs, 1), attr(TagKeyword, "a", []byte("b"))...),
		"bad integer":            append(append(header(OpGetJobs, 1), TagOperation), append(attr(TagInteger, "limit", []byte{1}), TagEnd)...),
		"stray endCollection":    append(append(header(OpGetJobs, 1), TagOperation), append(attr(TagEndCollection, "", nil), TagEnd)...),
		"open collection":        append(append(header(OpGetJobs, 1), TagJob), append(attr(TagBegCollection, "media-col", nil), TagEnd)...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(b)
			require.ErrorIs(t, err, ErrMalformed)
		})
	}
	// the header survives a cut attribute stream
	m, err := Parse(getPrinterAttrs[:40])
	require.Error(t, err)
	require.Equal(t, OpGetPrinterAttributes, m.Operation)
}

func TestEncodeRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 24, 9, 30, 5, 0, time.UTC)
	r := Response{Major: 2, Minor: 0, Status: StatusOK, RequestID: 9, Groups: []Group{
		OperationGroup("ok"),
		{Tag: TagPrinter, Attrs: []Attr{
			Keyword("sides-supported", "one-sided", "two-sided-long-edge"),
			Integer("queued-job-count", 0),
			Boolean("color-supported", false),
			Range("copies-supported", 1, 9999),
			Resolution("printer-resolution-default", 600, 600),
			DateTime("printer-current-time", now),
			Enum("printer-state", 3),
			NoValue("printer-location"),
		}},
	}}
	enc := r.Encode()
	require.Equal(t, []byte{2, 0, 0, 0, 0, 0, 0, 9, TagOperation}, enc[:9])
	require.Equal(t, TagEnd, enc[len(enc)-1])

	// a response has the request layout with the status in the operation slot
	m, err := Parse(enc)
	require.NoError(t, err)
	require.Equal(t, "ok", m.Get("operation", "status-message"))
	require.Equal(t, []string{"one-sided", "two-sided-long-edge"}, m.Values("printer", "sides-supported"))
	require.Equal(t, "1-9999", m.Get("printer", "copies-supported"))
	require.Equal(t, "600x600dpi", m.Get("printer", "printer-resolution-default"))
	require.Equal(t, "2026-10-24T09:30:05.0+00:00", m.Get("printer", "printer-current-time"))
	require.Equal(t, "false", m.Get("printer", "color-supported"))
	require.Equal(t, "no-value", m.Get("printer", "printer-location"))
}

func TestPrinterAttributesFilter(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	all := PrinterAttributes(DefaultPersona, "localhost:631", now, nil)
	require.Equal(t, all, PrinterAttributes(DefaultPersona, "localhost:631", now, []string{"all"}))
	names := []string{}
	for _, a := range all {
		names = append(names, a.Name)
	}
	require.Contains(t, names, "printer-uri-supported")
	require.Contains(t, names, "operations-supported")

	got := PrinterAttributes(DefaultPersona, "printer.local:631", now, []string{"printer-name", "printer-uri-supported", "nonexistent"})
	require.Equal(t, []Attr{
		Name("printer-name", "HP_LaserJet_Pro_M404n"),
		URI("printer-uri-supported", "ipp://printer.local:631/printers/HP_LaserJet_Pro_M404n"),
	}, got)
}

func TestURIHost(t *testing.T) {
	require.Equal(t, "203.0.113.5:631", URIHost("203.0.113.5:631"))
	require.Equal(t, "printer.local:631", URIHost("printer.local"))
	require.Equal(t, "[2001:db8::1]:631", URIHost("[2001:db8::1]"))
	require.Equal(t, "localhost:631", URIHost(""))
	require.Equal(t, "localhost:631", URIHost("evil/../x"))
	require.Equal(t, "localhost:631", URIHost(strings.Repeat("a", 300)))
}

func TestReadHeadAndBody(t *testing.T) {
	wire := "POST /printers/x HTTP/1.1\r\nHost: h:631\r\nContent-Type: application/ipp\r\n" +
		"Authorization: Basic YWRtaW46aHVudGVyMg==\r\nContent-Length: 5\r\n\r\nhelloGET / HTTP/1.0\r\n\r\n"
	r := bufio.NewReader(strings.NewReader(wire))
	req, raw, err := ReadHead(r)
	require.NoError(t, err)
	require.Equal(t, "POST", req.Method)
	require.Equal(t, "/printers/x", req.Path)
	require.True(t, req.IsIPP())
	require.True(t, req.KeepAlive())
	require.False(t, req.ExpectsContinue())
	user, pass, ok := req.BasicAuth()
	require.True(t, ok)
	require.Equal(t, "admin", user)
	require.Equal(t, "hunter2", pass)
	body, braw, truncated, err := ReadBody(r, req, 1024)
	require.NoError(t, err)
	require.False(t, truncated)
	require.Equal(t, "hello", string(body))
	require.Equal(t, wire[:strings.Index(wire, "GET ")], string(raw)+string(braw))

	req, _, err = ReadHead(r)
	require.NoError(t, err)
	require.Equal(t, "GET", req.Method)
	require.False(t, req.KeepAlive())
	require.False(t, req.HasBody())
	_, _, err = ReadHead(r)
	require.ErrorIs(t, err, io.EOF)
}

func TestReadBodyChunkedAndCaps(t *testing.T) {
	req := Request{Chunked: true, ContentLength: -1}
	wire := "5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: y\r\n\r\nNEXT"
	r := bufio.NewReader(strings.NewReader(wire))
	body, raw, truncated, err := ReadBody(r, req, 8)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Equal(t, "hello wo", string(body))
	require.Contains(t, string(raw), "hello\r\n")
	rest, _ := io.ReadAll(r)
	require.Equal(t, "NEXT", string(rest), "the discarded tail keeps the stream in sync")

	req = Request{ContentLength: 10}
	r = bufio.NewReader(strings.NewReader("0123456789NEXT"))
	body, raw, truncated, err = ReadBody(r, req, 4)
	require.NoError(t, err)
	require.True(t, truncated)
	require.Equal(t, "0123", string(body))
	require.Equal(t, "0123", string(raw))
	rest, _ = io.ReadAll(r)
	require.Equal(t, "NEXT", string(rest))

	_, _, _, err = ReadBody(bufio.NewReader(strings.NewReader("")), Request{ContentLength: maxDiscard + 100}, 4)
	require.ErrorIs(t, err, ErrBodyTooLarge)
	_, _, _, err = ReadBody(bufio.NewReader(strings.NewReader("zz\r\n")), Request{Chunked: true}, 4)
	require.ErrorIs(t, err, ErrMalformed)
	_, _, _, err = ReadBody(bufio.NewReader(strings.NewReader("012")), Request{ContentLength: 10}, 100)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadHeadMalformed(t *testing.T) {
	for name, wire := range map[string]string{
		"request line":   "HELLO\r\n\r\n",
		"header":         "GET / HTTP/1.1\r\nnocolon\r\n\r\n",
		"content length": "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
		"too many":       "GET / HTTP/1.1\r\n" + strings.Repeat("A: b\r\n", maxHeaders+2) + "\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, raw, err := ReadHead(bufio.NewReader(strings.NewReader(wire)))
			require.ErrorIs(t, err, ErrMalformed)
			require.NotEmpty(t, raw)
		})
	}
	_, _, err := ReadHead(bufio.NewReader(strings.NewReader("GET /" + strings.Repeat("a", 8192) + " HTTP/1.1\r\n")))
	require.True(t, errors.Is(err, ErrLineTooLong))
	_, raw, err := ReadHead(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\nHost: x")))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.True(t, bytes.HasPrefix(raw, []byte("GET / HTTP/1.1\r\n")))
}
