package mssqlbrowser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var testPersona = Persona{Server: "WIN-SQL01", Instance: "MSSQLSERVER", Version: "15.0.2000.5", TCPPort: 1433}

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		data []byte
		want Request
	}{
		{[]byte{0x02}, Request{Command: "CLNT_BCAST_EX"}},
		{[]byte{0x03}, Request{Command: "CLNT_UCAST_EX"}},
		{append([]byte{0x04}, "MSSQLSERVER\x00"...), Request{Command: "CLNT_UCAST_INST", Instance: "MSSQLSERVER"}},
		{append([]byte{0x04}, "SQLEXPRESS"...), Request{Command: "CLNT_UCAST_INST", Instance: "SQLEXPRESS"}},
		{append([]byte{0x0f, 0x01}, "MSSQLSERVER\x00"...), Request{Command: "CLNT_UCAST_DAC", Instance: "MSSQLSERVER"}},
		{nil, Request{}},
		{[]byte{0x02, 0x00}, Request{}},
		{[]byte{0x04}, Request{}},
		{[]byte{0x04, 0x00}, Request{}},
		{append([]byte{0x04}, "A\x00B"...), Request{}},
		{append([]byte{0x04}, "0123456789012345678901234567890123"...), Request{}},
		{[]byte{0x0f, 0x02, 'A'}, Request{}},
		{[]byte("\r\n"), Request{}},
	} {
		require.Equal(t, tc.want, Parse(tc.data), "%x", tc.data)
	}
}

func TestReply(t *testing.T) {
	desc := `ServerName;WIN-SQL01;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.2000.5;tcp;1433;np;\\WIN-SQL01\pipe\sql\query;;`
	want := append([]byte{0x05, byte(len(desc)), 0x00}, desc...)

	for _, req := range []Request{
		{Command: "CLNT_BCAST_EX"},
		{Command: "CLNT_UCAST_EX"},
		{Command: "CLNT_UCAST_INST", Instance: "mssqlserver"},
	} {
		got, status := Reply(req, testPersona)
		require.Equal(t, want, got, req.Command)
		require.Equal(t, "SVR_RESP", status)
	}

	for _, req := range []Request{
		{},
		{Command: "CLNT_UCAST_INST", Instance: "SQLEXPRESS"},
		{Command: "CLNT_UCAST_DAC", Instance: "MSSQLSERVER"},
	} {
		got, status := Reply(req, testPersona)
		require.Nil(t, got, req.Command)
		require.Empty(t, status)
	}
}
