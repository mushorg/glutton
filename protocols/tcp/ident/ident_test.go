package ident

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseQuery(t *testing.T) {
	cases := []struct {
		in string
		q  Query
		ok bool
	}{
		// Captured: Ochi event 231284cf-a634-469d-95c0-a70e859aabad.
		{"6191, 23\n", Query{6191, 23}, true},
		{"6191 , 23\r\n", Query{6191, 23}, true},
		{"  80,1234", Query{80, 1234}, true},
		{"00080,00023\r\n", Query{80, 23}, true},
		{"0, 23\n", Query{0, 23}, true},
		{"99999, 1\n", Query{99999, 1}, true},
		{"123456, 1\n", Query{}, false},
		{"6191\n", Query{}, false},
		{"6191, 23, 1\n", Query{}, false},
		{"6191, 23 : USERID\n", Query{}, false},
		{"GET / HTTP/1.0\r\n", Query{}, false},
		{"", Query{}, false},
	}
	for _, c := range cases {
		q, ok := ParseQuery([]byte(c.in))
		require.Equal(t, c.ok, ok, "%q", c.in)
		require.Equal(t, c.q, q, "%q", c.in)
	}
}

func TestBuildReply(t *testing.T) {
	require.Equal(t, "6191, 23 : ERROR : NO-USER\r\n", string(BuildReply(Query{6191, 23})))
	require.Equal(t, "0, 23 : ERROR : INVALID-PORT\r\n", string(BuildReply(Query{0, 23})))
	require.Equal(t, "99999, 1 : ERROR : INVALID-PORT\r\n", string(BuildReply(Query{99999, 1})))
	require.Equal(t, "65535, 65535 : ERROR : NO-USER\r\n", string(BuildReply(Query{65535, 65535})))
}
