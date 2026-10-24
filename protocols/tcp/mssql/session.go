package mssql

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mushorg/glutton/protocols/helpers/ntlm"
)

// Tokens sent after a successful login (MS-TDS 2.2.7).
const (
	tokenReturnStatus = 0x79
	tokenColMetadata  = 0x81
	tokenInfo         = 0xab
	tokenLoginAck     = 0xad
	tokenRow          = 0xd1
	tokenEnvChange    = 0xe3
	tokenDoneProc     = 0xfe
	tokenDoneInProc   = 0xff
)

// DONE status bits and CurCmd values.
const (
	doneMore      = 0x0001
	doneCount     = 0x0010
	doneAttn      = 0x0020
	curCmdSelect  = 0xc1
	curCmdExecute = 0xe0
)

// ENVCHANGE types.
const (
	envDatabase   = 1
	envLanguage   = 2
	envPacketSize = 4
	envCollation  = 7
)

const (
	typeNVarChar = 0xe7
	typeNChar    = 0xef
	plpNull      = 0xffffffffffffffff
	tdsVersion71 = 0x71000000
	tdsVersion74 = 0x74000004
)

// Informational messages (sys.messages).
const (
	InfoDatabaseChanged = 5701
	InfoLanguageChanged = 5703
	InfoConfigChanged   = 15457
)

// defaultPacketSize is the packet size SQL Server reports when the client asks
// for one outside 512..32767.
const defaultPacketSize = 4096

// collation is SQL_Latin1_General_CP1_CI_AS, the default server collation.
var collation = []byte{0x09, 0x04, 0xd0, 0x00, 0x34}

// progName is the LOGINACK ProgName; SQL Server pads it with two NULs.
const progName = "Microsoft SQL Server\x00\x00"

// Version is the @@VERSION string matching ServerVersion, on the Windows
// Server 2019 (build 17763) the NTLM CHALLENGE reports.
const Version = "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) \n" +
	"\tSep 24 2019 13:48:23 \n" +
	"\tCopyright (C) 2019 Microsoft Corporation\n" +
	"\tStandard Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)\n"

// cmdShellUser is the xp_cmdshell account of a default instance.
const cmdShellUser = `nt service\mssqlserver`

// maxStatements bounds the statements of one batch that get a reply.
const maxStatements = 16

// tokenWriter appends a token stream. legacy selects the pre-TDS 7.2 widths
// (2-byte line numbers and UserType, 4-byte row counts); noCollation drops the
// collation TDS 7.0 does not know.
type tokenWriter struct {
	b           []byte
	legacy      bool
	noCollation bool
}

func newTokenWriter(tdsVersion uint32) *tokenWriter {
	return &tokenWriter{legacy: LegacyTDS(tdsVersion), noCollation: tdsVersion < tdsVersion71}
}

func bVarChar(s string) []byte {
	u := ntlm.EncodeUTF16LE(s)
	if len(u) > 255*2 {
		u = u[:255*2]
	}
	return append([]byte{byte(len(u) / 2)}, u...)
}

func (w *tokenWriter) envChange(typ byte, newVal, oldVal []byte) {
	body := append([]byte{typ}, newVal...)
	body = append(body, oldVal...)
	w.b = append(w.b, tokenEnvChange)
	w.b = binary.LittleEndian.AppendUint16(w.b, uint16(len(body)))
	w.b = append(w.b, body...)
}

// message appends an ERROR or INFO token.
func (w *tokenWriter) message(token byte, number uint32, state, class byte, msg, server string) {
	le := binary.LittleEndian
	text := ntlm.EncodeUTF16LE(msg)
	var body []byte
	body = le.AppendUint32(body, number)
	body = append(body, state, class)
	body = le.AppendUint16(body, uint16(len(text)/2))
	body = append(body, text...)
	body = append(body, bVarChar(server)...)
	body = append(body, 0) // ProcName
	if w.legacy {
		body = le.AppendUint16(body, 1)
	} else {
		body = le.AppendUint32(body, 1)
	}
	w.b = append(w.b, token)
	w.b = le.AppendUint16(w.b, uint16(len(body)))
	w.b = append(w.b, body...)
}

// done appends a DONE, DONEPROC or DONEINPROC token.
func (w *tokenWriter) done(token byte, status, curCmd uint16, rows uint64) {
	le := binary.LittleEndian
	w.b = append(w.b, token)
	w.b = le.AppendUint16(w.b, status)
	w.b = le.AppendUint16(w.b, curCmd)
	if w.legacy {
		w.b = le.AppendUint32(w.b, uint32(rows))
	} else {
		w.b = le.AppendUint64(w.b, rows)
	}
}

func (w *tokenWriter) returnStatus() {
	w.b = append(w.b, tokenReturnStatus, 0, 0, 0, 0)
}

// column is an NVARCHAR result column.
type column struct {
	name     string
	maxChars int
}

// rows appends COLMETADATA for col and one ROW per value; a nil value is NULL.
func (w *tokenWriter) rows(col column, values []*string) {
	le := binary.LittleEndian
	w.b = append(w.b, tokenColMetadata)
	w.b = le.AppendUint16(w.b, 1)
	if w.legacy {
		w.b = le.AppendUint16(w.b, 0) // UserType
	} else {
		w.b = le.AppendUint32(w.b, 0)
	}
	w.b = le.AppendUint16(w.b, 0x0001) // Flags: nullable
	w.b = append(w.b, typeNVarChar)
	w.b = le.AppendUint16(w.b, uint16(col.maxChars*2))
	if !w.noCollation {
		w.b = append(w.b, collation...)
	}
	w.b = append(w.b, bVarChar(col.name)...)
	for _, v := range values {
		w.b = append(w.b, tokenRow)
		if v == nil {
			w.b = le.AppendUint16(w.b, 0xffff)
			continue
		}
		u := ntlm.EncodeUTF16LE(*v)
		if len(u) > col.maxChars*2 {
			u = u[:col.maxChars*2]
		}
		w.b = le.AppendUint16(w.b, uint16(len(u)))
		w.b = append(w.b, u...)
	}
}

// AckTDSVersion is the TDS version the server answers a LOGIN7 TDSVersion
// with: the highest one it knows that the client offered.
func AckTDSVersion(v uint32) uint32 {
	for _, known := range []uint32{tdsVersion74, 0x730b0003, 0x730a0003, tdsVersion72, 0x71000001, tdsVersion71} {
		if v >= known {
			return known
		}
	}
	return 0x70000000
}

// LoginAckOptions configures the reply to an accepted LOGIN7.
type LoginAckOptions struct {
	// TDSVersion is the client's LOGIN7 TDSVersion.
	TDSVersion uint32
	// PacketSize, Database and Language are what the client asked for.
	PacketSize uint32
	Database   string
	Language   string
	// Server is the computer name in the INFO messages.
	Server string
}

// BuildLoginAck builds the token stream SQL Server sends for a successful
// login: database and language changes with their INFO messages, the
// collation, LOGINACK, the packet size and a final DONE.
func BuildLoginAck(o LoginAckOptions) []byte {
	ack := AckTDSVersion(o.TDSVersion)
	w := newTokenWriter(ack)
	db := o.Database
	if db == "" {
		db = "master"
	}
	lang := o.Language
	if lang == "" {
		lang = "us_english"
	}
	size := o.PacketSize
	if size < 512 || size > 32767 {
		size = defaultPacketSize
	}

	w.envChange(envDatabase, bVarChar(db), bVarChar("master"))
	w.message(tokenInfo, InfoDatabaseChanged, 2, 0, "Changed database context to '"+db+"'.", o.Server)
	if !w.noCollation {
		w.envChange(envCollation, append([]byte{byte(len(collation))}, collation...), []byte{0})
	}
	w.envChange(envLanguage, bVarChar(lang), bVarChar(""))
	w.message(tokenInfo, InfoLanguageChanged, 1, 0, "Changed language setting to "+lang+".", o.Server)

	prog := bVarChar(progName)
	w.b = append(w.b, tokenLoginAck)
	w.b = binary.LittleEndian.AppendUint16(w.b, uint16(1+4+len(prog)+4))
	w.b = append(w.b, 1) // Interface: SQL
	w.b = binary.BigEndian.AppendUint32(w.b, ack)
	w.b = append(w.b, prog...)
	w.b = append(w.b, ServerVersion[:4]...)

	w.envChange(envPacketSize, bVarChar(strconv.Itoa(int(size))), bVarChar(strconv.Itoa(defaultPacketSize)))
	w.done(tokenDone, 0, 0, 0)
	return packet(TypeTabular, w.b)
}

// QueryOptions configures the canned replies to requests after login.
type QueryOptions struct {
	// TDSVersion is the client's LOGIN7 TDSVersion.
	TDSVersion uint32
	// Server is the computer name for @@SERVERNAME, hostname and INFO
	// messages.
	Server string
}

// Reply status names.
const (
	StatusResult = "result"
	StatusDone   = "done"
)

// statementRe finds the statements that get more than a bare DONE.
var statementRe = regexp.MustCompile(`(?i)@@version|@@servername|` +
	`sp_configure\s*N?'([^']*)'(?:\s*,\s*N?'?(\d+))?|` +
	`xp_cmdshell(?:\s+N?'((?:[^']|'')*)')?`)

// configOptions are sp_configure names that sp_configure echoes in full when
// given a prefix.
var configOptions = []string{
	"show advanced options", "xp_cmdshell", "Ole Automation Procedures",
	"clr enabled", "clr strict security", "Ad Hoc Distributed Queries", "Agent XPs",
}

func configOptionName(given string) string {
	g := strings.ToLower(strings.TrimSpace(given))
	for _, name := range configOptions {
		if g != "" && strings.HasPrefix(strings.ToLower(name), g) {
			return name
		}
	}
	return given
}

// cmdShellOutput is the xp_cmdshell output of cmd: the account for whoami,
// the server for hostname, then the trailing NULL row xp_cmdshell always
// returns.
func cmdShellOutput(cmd, server string) []*string {
	fields := strings.Fields(strings.ToLower(strings.ReplaceAll(cmd, "''", "'")))
	var out []*string
	if len(fields) > 0 {
		switch strings.TrimSuffix(fields[len(fields)-1], ".exe") {
		case "whoami":
			s := cmdShellUser
			out = append(out, &s)
		case "hostname":
			s := server
			out = append(out, &s)
		}
	}
	return append(out, nil)
}

// statements appends the replies to the statements of query. The last token
// carries doneMore when more is set (another token follows).
func (w *tokenWriter) statements(query string, server string, more bool) (results bool) {
	matches := statementRe.FindAllStringSubmatchIndex(query, maxStatements)
	if len(matches) == 0 {
		var status uint16
		if more {
			status = doneMore
		}
		w.done(tokenDone, status, 0, 0)
		return false
	}
	group := func(m []int, i int) string {
		if m[2*i] < 0 {
			return ""
		}
		return query[m[2*i]:m[2*i+1]]
	}
	for i, m := range matches {
		var status uint16
		if more || i < len(matches)-1 {
			status = doneMore
		}
		switch stmt := strings.ToLower(query[m[0]:m[1]]); {
		case stmt == "@@version":
			v := Version
			w.rows(column{maxChars: 300}, []*string{&v})
			w.done(tokenDone, status|doneCount, curCmdSelect, 1)
			results = true
		case stmt == "@@servername":
			s := server
			w.rows(column{maxChars: 128}, []*string{&s})
			w.done(tokenDone, status|doneCount, curCmdSelect, 1)
			results = true
		case strings.HasPrefix(stmt, "sp_configure"):
			if to := group(m, 2); to != "" {
				from := "0"
				if to == "0" {
					from = "1"
				}
				w.message(tokenInfo, InfoConfigChanged, 1, 0, fmt.Sprintf(
					"Configuration option '%s' changed from %s to %s. Run the RECONFIGURE statement to install.",
					configOptionName(group(m, 1)), from, to), server)
			}
			w.returnStatus()
			w.done(tokenDoneProc, status, curCmdExecute, 0)
		default: // xp_cmdshell
			out := cmdShellOutput(group(m, 3), server)
			w.rows(column{name: "output", maxChars: 255}, out)
			w.done(tokenDoneInProc, doneMore|doneCount, curCmdSelect, uint64(len(out)))
			w.returnStatus()
			w.done(tokenDoneProc, status, curCmdExecute, 0)
			results = true
		}
	}
	return results
}

// BuildBatchReply builds the reply to a SQL batch: a result for @@VERSION,
// @@SERVERNAME and xp_cmdshell, the RECONFIGURE hint for sp_configure, and a
// bare DONE for everything else. Nothing in the query is executed. status is
// StatusResult when a result set was sent, else StatusDone.
func BuildBatchReply(query string, o QueryOptions) (data []byte, status string) {
	w := newTokenWriter(o.TDSVersion)
	status = StatusDone
	if w.statements(query, o.Server, false) {
		status = StatusResult
	}
	return packet(TypeTabular, w.b), status
}

// BuildRPCReply builds the reply to an RPC request: the replies to its
// statement (sp_executesql), then RETURNSTATUS 0 and a final DONEPROC.
func BuildRPCReply(statement string, o QueryOptions) (data []byte, status string) {
	w := newTokenWriter(o.TDSVersion)
	status = StatusDone
	if statement != "" && w.statements(statement, o.Server, true) {
		status = StatusResult
	}
	w.returnStatus()
	w.done(tokenDoneProc, 0, 0, 0)
	return packet(TypeTabular, w.b), status
}

// BuildAttentionAck acknowledges an ATTENTION (cancel) with DONE_ATTN.
func BuildAttentionAck(tdsVersion uint32) []byte {
	w := newTokenWriter(tdsVersion)
	w.done(tokenDone, doneAttn, 0, 0)
	return packet(TypeTabular, w.b)
}

// BuildDone is a bare final DONE, the reply to a request with nothing to
// return.
func BuildDone(tdsVersion uint32) []byte {
	w := newTokenWriter(tdsVersion)
	w.done(tokenDone, 0, 0, 0)
	return packet(TypeTabular, w.b)
}

// skipAllHeaders returns data after its ALL_HEADERS block (TDS 7.2+), or data
// itself when it does not start with a well-formed one (TDS 7.1).
func skipAllHeaders(data []byte) []byte {
	le := binary.LittleEndian
	if len(data) < 4 {
		return data
	}
	total := int(le.Uint32(data))
	if total < 10 || total > len(data) {
		return data
	}
	for off := 4; off < total; {
		if off+6 > total {
			return data
		}
		n := int(le.Uint32(data[off:]))
		typ := le.Uint16(data[off+4:])
		if n < 6 || n > total-off || typ < 1 || typ > 3 {
			return data
		}
		off += n
	}
	return data[total:]
}

func decodeUTF16(b []byte) string {
	return ntlm.DecodeUTF16LE(b[:len(b)&^1])
}

// ParseSQLBatch returns the query text of a SQL_BATCH message body.
func ParseSQLBatch(data []byte) string {
	return decodeUTF16(skipAllHeaders(data))
}

// rpcProcs names the well-known stored procedures an RPC request can name by
// ProcID instead of by name.
var rpcProcs = map[uint16]string{
	1: "sp_cursor", 2: "sp_cursoropen", 3: "sp_cursorprepare", 4: "sp_cursorexecute",
	5: "sp_cursorprepexec", 6: "sp_cursorunprepare", 7: "sp_cursorfetch", 8: "sp_cursoroption",
	9: "sp_cursorclose", 10: "sp_executesql", 11: "sp_prepare", 12: "sp_execute",
	13: "sp_prepexec", 14: "sp_prepexecrpc", 15: "sp_unprepare",
}

// RPC is the first call of an RPC request.
type RPC struct {
	// Proc is the procedure name, or the well-known name of its ProcID.
	Proc string
	// Statement is the first parameter of sp_executesql.
	Statement string
}

// ParseRPC parses the first call of an RPC request body.
func ParseRPC(data []byte) RPC {
	le := binary.LittleEndian
	var r RPC
	b := skipAllHeaders(data)
	if len(b) < 2 {
		return r
	}
	n := int(le.Uint16(b))
	b = b[2:]
	if n == 0xffff {
		if len(b) < 2 {
			return r
		}
		id := le.Uint16(b)
		r.Proc = rpcProcs[id]
		if r.Proc == "" {
			r.Proc = fmt.Sprintf("proc_%d", id)
		}
		b = b[2:]
	} else {
		if len(b) < 2*n {
			return r
		}
		r.Proc = decodeUTF16(b[:2*n])
		b = b[2*n:]
	}
	if len(b) < 2 || !strings.EqualFold(r.Proc, "sp_executesql") {
		return r
	}
	r.Statement = firstStringParam(b[2:]) // after OptionFlags
	return r
}

// firstStringParam returns the value of the first RPC parameter when it is an
// NVARCHAR or NCHAR (TDS 7.1+ TYPE_INFO with collation).
func firstStringParam(b []byte) string {
	le := binary.LittleEndian
	if len(b) < 1 {
		return ""
	}
	nameLen := 1 + 2*int(b[0])
	if len(b) < nameLen+1+1+2+5 {
		return ""
	}
	b = b[nameLen+1:] // name, StatusFlags
	if b[0] != typeNVarChar && b[0] != typeNChar {
		return ""
	}
	maxLen := le.Uint16(b[1:])
	b = b[1+2+5:]
	if maxLen != 0xffff {
		if len(b) < 2 {
			return ""
		}
		n := int(le.Uint16(b))
		if n == 0xffff || len(b) < 2+n {
			return ""
		}
		return decodeUTF16(b[2 : 2+n])
	}
	// PLP: total length, then chunks up to a zero terminator
	if len(b) < 8 || le.Uint64(b) == plpNull {
		return ""
	}
	b = b[8:]
	var out []byte
	for len(b) >= 4 {
		n := int(le.Uint32(b))
		if n == 0 || n > len(b)-4 {
			break
		}
		out = append(out, b[4:4+n]...)
		b = b[4+n:]
	}
	return decodeUTF16(out)
}

// binaryBlobRe matches a PE image passed as a hex literal or base64, as CLR
// assembly and dropper queries carry.
var binaryBlobRe = regexp.MustCompile(`(?i)0x4d5a|TVqQAAMAAAAEAAAA`)

// LooksLikeBinaryBlob reports whether query carries an embedded executable.
func LooksLikeBinaryBlob(query string) bool {
	return binaryBlobRe.MatchString(query)
}
