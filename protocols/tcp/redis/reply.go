package redis

import (
	"strconv"
	"strings"
)

// Reply status names recorded on write frames for non-string replies.
const (
	StatusBulk    = "bulk"
	StatusNil     = "nil"
	StatusInteger = "integer"
	StatusArray   = "array"
)

// Reply is an encoded RESP2 reply and its status name: the text of a simple
// string (OK, PONG), the code of an error (ERR, NOSCRIPT), or one of the
// Status constants.
type Reply struct {
	Data   []byte
	Status string
}

// Simple encodes a simple string, "+OK\r\n".
func Simple(s string) Reply {
	return Reply{Data: []byte("+" + s + "\r\n"), Status: s}
}

// Error encodes an error reply; msg starts with the error code ("ERR ...").
func Error(msg string) Reply {
	code, _, _ := strings.Cut(msg, " ")
	return Reply{Data: []byte("-" + msg + "\r\n"), Status: code}
}

// Integer encodes an integer reply.
func Integer(n int64) Reply {
	return Reply{Data: []byte(":" + strconv.FormatInt(n, 10) + "\r\n"), Status: StatusInteger}
}

// Bulk encodes a bulk string.
func Bulk(b []byte) Reply {
	return Reply{Data: appendBulk(nil, b), Status: StatusBulk}
}

// Nil encodes the null bulk string.
func Nil() Reply {
	return Reply{Data: []byte("$-1\r\n"), Status: StatusNil}
}

// Array encodes an array of bulk strings.
func Array(items ...string) Reply {
	b := []byte("*" + strconv.Itoa(len(items)) + "\r\n")
	for _, it := range items {
		b = appendBulk(b, []byte(it))
	}
	return Reply{Data: b, Status: StatusArray}
}

// Scan encodes a SCAN reply: the next cursor and a page of keys.
func Scan(cursor string, keys []string) Reply {
	b := []byte("*2\r\n")
	b = appendBulk(b, []byte(cursor))
	b = append(b, Array(keys...).Data...)
	return Reply{Data: b, Status: StatusArray}
}

func appendBulk(b, data []byte) []byte {
	b = append(b, '$')
	b = strconv.AppendInt(b, int64(len(data)), 10)
	b = append(b, '\r', '\n')
	b = append(b, data...)
	return append(b, '\r', '\n')
}

// UnknownCommand is the Redis 5 reply for a command it does not know.
func UnknownCommand(args [][]byte) Reply {
	var b strings.Builder
	b.WriteString("ERR unknown command `")
	b.WriteString(sanitize(args[0], 128))
	b.WriteString("`, with args beginning with: ")
	for _, a := range args[1:] {
		b.WriteString("`")
		b.WriteString(sanitize(a, 128))
		b.WriteString("`, ")
		if b.Len() >= 512 {
			break
		}
	}
	return Error(b.String())
}

// WrongArity is the reply for a known command with the wrong argument count.
func WrongArity(name string) Reply {
	return Error("ERR wrong number of arguments for '" + name + "' command")
}

// UnknownSubcommand is the Redis 5 reply for an unknown container subcommand.
func UnknownSubcommand(container, sub string) Reply {
	return Error("ERR Unknown subcommand or wrong number of arguments for '" +
		sanitize([]byte(sub), 128) + "'. Try " + strings.ToUpper(container) + " HELP.")
}

// ProtocolErrorReply is sent before the server closes on a malformed request.
func ProtocolErrorReply(e *ProtocolError) Reply {
	return Error("ERR Protocol error: " + e.Msg)
}

// sanitize truncates b and drops the CR/LF that would break an error line,
// as the server does when quoting client input in an error.
func sanitize(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, string(b))
}
