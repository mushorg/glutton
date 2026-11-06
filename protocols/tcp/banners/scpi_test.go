package banners

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSCPIIdentify(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("*IDN?\n"), // 2026-11-06 22:01:38 UTC, tcp/5025
		[]byte("*IDN?\r\n"),
		[]byte("*IDN?"),
		[]byte("*idn?\n"),
	} {
		resp, ok := ForPayload(data)
		require.True(t, ok, "%q", data)
		require.Equal(t, Response{Name: "scpi-idn", Data: scpiIdentity}, resp)
	}

	for _, data := range [][]byte{
		[]byte("*IDN"),
		[]byte("*IDN?;*OPT?\n"),
		[]byte(" *IDN?\n"),
		[]byte(""),
	} {
		_, ok := scpiReply(data)
		require.False(t, ok, "%q", data)
	}
}

func TestSCPIIdentityFormat(t *testing.T) {
	require.True(t, bytes.HasSuffix(scpiIdentity, []byte("\n")))
	require.Len(t, bytes.Split(bytes.TrimSuffix(scpiIdentity, []byte("\n")), []byte(",")), 4)
}

func TestSCPIPort(t *testing.T) {
	resp, ok := ForPort(5025)
	require.True(t, ok)
	require.Equal(t, Response{Name: "scpi", NoReply: true}, resp)
}
