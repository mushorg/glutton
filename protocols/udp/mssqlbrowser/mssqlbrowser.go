// Package mssqlbrowser parses SQL Server Resolution Protocol (MC-SQLR)
// requests sent to the SQL Server Browser on udp/1434 and builds its
// SVR_RESP replies.
//
// Layouts follow [MC-SQLR] section 2.2: CLNT_BCAST_EX (0x02) and
// CLNT_UCAST_EX (0x03) are a single byte asking for every instance;
// CLNT_UCAST_INST (0x04) is followed by a NUL-terminated instance name of at
// most 32 bytes; CLNT_UCAST_DAC (0x0F) is followed by protocol version 0x01
// and an instance name. SVR_RESP is 0x05, a little-endian uint16 length and
// the semicolon-separated instance description.
package mssqlbrowser

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

// Request types.
const (
	ClntBcastEx   = 0x02
	ClntUcastEx   = 0x03
	ClntUcastInst = 0x04
	ClntUcastDAC  = 0x0f
	SvrResp       = 0x05

	// maxInstanceName is the MC-SQLR limit on an instance name, NUL included.
	maxInstanceName = 32
)

// Request is a parsed MC-SQLR request.
type Request struct {
	Command  string // CLNT_BCAST_EX, CLNT_UCAST_EX, CLNT_UCAST_INST, CLNT_UCAST_DAC or ""
	Instance string // requested instance name (CLNT_UCAST_INST, CLNT_UCAST_DAC)
}

// Parse names an MC-SQLR request. Unknown or malformed datagrams return a
// zero Request.
func Parse(data []byte) Request {
	if len(data) == 0 {
		return Request{}
	}
	switch data[0] {
	case ClntBcastEx:
		if len(data) == 1 {
			return Request{Command: "CLNT_BCAST_EX"}
		}
	case ClntUcastEx:
		if len(data) == 1 {
			return Request{Command: "CLNT_UCAST_EX"}
		}
	case ClntUcastInst:
		if name, ok := instanceName(data[1:]); ok {
			return Request{Command: "CLNT_UCAST_INST", Instance: name}
		}
	case ClntUcastDAC:
		if len(data) >= 2 && data[1] == 0x01 {
			if name, ok := instanceName(data[2:]); ok {
				return Request{Command: "CLNT_UCAST_DAC", Instance: name}
			}
		}
	}
	return Request{}
}

// instanceName reads a NUL-terminated name (the terminator is optional at the
// end of the datagram) of at most 32 bytes.
func instanceName(b []byte) (string, bool) {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		if i+1 != len(b) {
			return "", false
		}
		b = b[:i]
	}
	if len(b) == 0 || len(b) >= maxInstanceName {
		return "", false
	}
	return string(b), true
}

// Persona is the SQL Server instance the replies describe.
type Persona struct {
	Server   string // NetBIOS host name
	Instance string // instance name; MSSQLSERVER is the default instance
	Version  string // product version
	TCPPort  int
}

// Description renders the RESP_DATA instance record.
func (p Persona) Description() string {
	return "ServerName;" + p.Server +
		";InstanceName;" + p.Instance +
		";IsClustered;No;Version;" + p.Version +
		";tcp;" + strconv.Itoa(p.TCPPort) +
		";np;\\\\" + p.Server + "\\pipe\\sql\\query;;"
}

// Reply returns the SVR_RESP for req and its status label, or nil when a
// real Browser stays silent: unknown requests, a unicast instance query for
// an instance the persona does not have, and DAC requests (the dedicated
// admin connection is not emulated).
func Reply(req Request, p Persona) ([]byte, string) {
	switch req.Command {
	case "CLNT_BCAST_EX", "CLNT_UCAST_EX":
	case "CLNT_UCAST_INST":
		if !strings.EqualFold(req.Instance, p.Instance) {
			return nil, ""
		}
	default:
		return nil, ""
	}
	desc := p.Description()
	out := make([]byte, 3, 3+len(desc))
	out[0] = SvrResp
	binary.LittleEndian.PutUint16(out[1:3], uint16(len(desc)))
	return append(out, desc...), "SVR_RESP"
}
