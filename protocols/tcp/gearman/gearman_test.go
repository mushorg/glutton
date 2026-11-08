package gearman

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// Captured Censys probe (run-1794151704-1.jsonl event #3): ECHO_REQ "*".
var capturedEcho = []byte{0x00, 0x52, 0x45, 0x51, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x2a}

func TestReadPacketCapturedEcho(t *testing.T) {
	p, err := ReadPacket(bytes.NewReader(capturedEcho))
	require.NoError(t, err)
	require.Equal(t, "REQ", p.Magic)
	require.Equal(t, EchoReq, p.Type)
	require.Equal(t, "ECHO_REQ", p.Name())
	require.Equal(t, [][]byte{[]byte("*")}, p.Args)
	require.Equal(t, capturedEcho, p.Raw)
}

func TestReplyEcho(t *testing.T) {
	p, err := ReadPacket(bytes.NewReader(capturedEcho))
	require.NoError(t, err)
	got := NewServer("h").Reply(p)
	require.Equal(t, []byte{0x00, 'R', 'E', 'S', 0, 0, 0, 17, 0, 0, 0, 1, '*'}, got)
}

func TestSubmitJobArgsAndHandle(t *testing.T) {
	pkt := Encode(MagicReq, SubmitJobBg, []byte("reverse"), []byte("u1"), []byte("a\x00b"))
	p, err := ReadPacket(bytes.NewReader(pkt))
	require.NoError(t, err)
	require.Equal(t, "reverse", p.Function())
	require.Equal(t, "u1", p.Unique())
	require.Equal(t, []byte("a\x00b"), p.Args[2])

	s := NewServer("ip-10-0-1-17")
	r1, err := ReadPacket(bytes.NewReader(s.Reply(p)))
	require.NoError(t, err)
	require.Equal(t, "RES", r1.Magic)
	require.Equal(t, JobCreated, r1.Type)
	require.Equal(t, "H:ip-10-0-1-17:1", r1.Handle())
	r2, _ := ReadPacket(bytes.NewReader(s.Reply(p)))
	require.Equal(t, "H:ip-10-0-1-17:2", r2.Handle())
}

func TestReplyOthers(t *testing.T) {
	s := NewServer("h")
	read := func(b []byte) Packet {
		p, err := ReadPacket(bytes.NewReader(b))
		require.NoError(t, err)
		return p
	}
	st := read(s.Reply(read(Encode(MagicReq, GetStatus, []byte("H:x:1")))))
	require.Equal(t, StatusRes, st.Type)
	require.Equal(t, "H:x:1", st.Handle())

	require.Equal(t, NoJob, read(s.Reply(read(Encode(MagicReq, GrabJob)))).Type)
	require.Nil(t, s.Reply(read(Encode(MagicReq, CanDo, []byte("fn")))))
	require.Equal(t, OptionRes, read(s.Reply(read(Encode(MagicReq, OptionReq, []byte("exceptions"))))).Type)
	require.Equal(t, Error, read(s.Reply(read(Encode(MagicReq, 99)))).Type)
	require.Nil(t, s.Reply(read(Encode(MagicRes, EchoRes, []byte("x")))))
	require.Equal(t, "UNKNOWN_99", TypeName(99))
}

func TestReadPacketErrors(t *testing.T) {
	_, err := ReadPacket(bytes.NewReader([]byte("GET / HTTP/1.1\r\n")))
	require.ErrorIs(t, err, ErrBadMagic)

	hdr := make([]byte, HeaderSize)
	copy(hdr, MagicReq)
	binary.BigEndian.PutUint32(hdr[4:8], EchoReq)
	binary.BigEndian.PutUint32(hdr[8:12], MaxBodySize+1)
	p, err := ReadPacket(bytes.NewReader(hdr))
	require.ErrorIs(t, err, ErrTooLarge)
	require.Equal(t, hdr, p.Raw)

	p, err = ReadPacket(bytes.NewReader(capturedEcho[:12]))
	require.Error(t, err)
	require.Len(t, p.Raw, 12)
}

func TestAdminReply(t *testing.T) {
	s := NewServer("h")
	r, closeAfter := s.AdminReply("version\r\n", "203.0.113.5")
	require.Equal(t, "OK 1.1.19.1\n", string(r))
	require.False(t, closeAfter)
	r, _ = s.AdminReply("STATUS", "203.0.113.5")
	require.Equal(t, ".\n", string(r))
	r, _ = s.AdminReply("workers", "203.0.113.5")
	require.Equal(t, "33 203.0.113.5 - :\n.\n", string(r))
	r, _ = s.AdminReply("GET / HTTP/1.1", "203.0.113.5")
	require.Equal(t, "ERR UNKNOWN_COMMAND Unknown+server+command\n", string(r))
	_, closeAfter = s.AdminReply("shutdown graceful", "203.0.113.5")
	require.True(t, closeAfter)
	r, _ = s.AdminReply("  ", "x")
	require.Nil(t, r)
}
