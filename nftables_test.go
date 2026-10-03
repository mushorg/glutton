package glutton

import (
	"bytes"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPaddedIfaceName(t *testing.T) {
	got := paddedIfaceName("eth0")
	require.Len(t, got, unix.IFNAMSIZ)
	require.Equal(t, []byte("eth0\x00"), got[:5])
	require.Equal(t, byte(0), got[15])
}

func TestTProxyRuleExprsTCP(t *testing.T) {
	exprs := tproxyRuleExprs("eth0", unix.IPPROTO_TCP, 2222, 5000)
	assertTProxyRuleExprs(t, exprs, "eth0", unix.IPPROTO_TCP, 2222, 5000)
}

func TestTProxyRuleExprsUDP(t *testing.T) {
	exprs := tproxyRuleExprs("eth0", unix.IPPROTO_UDP, 22, 5001)
	assertTProxyRuleExprs(t, exprs, "eth0", unix.IPPROTO_UDP, 22, 5001)
}

func assertTProxyRuleExprs(t *testing.T, exprs []expr.Any, iface string, proto uint8, sshPort, dport uint16) {
	t.Helper()

	var (
		gotIface   []byte
		gotProto   []byte
		gotSSHPort []byte
		gotSSHOp   expr.CmpOp
		gotCTEq    bool
		gotAddr    []byte
		gotPort    []byte
		gotTProxy  *expr.TProxy
		loadedDst  bool
	)

	for i, e := range exprs {
		switch v := e.(type) {
		case *expr.Meta:
			if v.Key == expr.MetaKeyIIFNAME {
				cmp, ok := exprs[i+1].(*expr.Cmp)
				require.True(t, ok, "iifname must be followed by a compare")
				gotIface = cmp.Data
			}
			if v.Key == expr.MetaKeyL4PROTO {
				cmp, ok := exprs[i+1].(*expr.Cmp)
				require.True(t, ok, "l4proto must be followed by a compare")
				gotProto = cmp.Data
			}
		case *expr.Payload:
			if v.Base == expr.PayloadBaseTransportHeader && v.Offset == 2 && v.Len == 2 {
				loadedDst = true
				cmp, ok := exprs[i+1].(*expr.Cmp)
				require.True(t, ok, "dport payload must be followed by a compare")
				gotSSHPort = cmp.Data
				gotSSHOp = cmp.Op
			}
		case *expr.Bitwise:
			cmp, ok := exprs[i+1].(*expr.Cmp)
			require.True(t, ok, "ct bitwise must be followed by a compare")
			require.Equal(t, expr.CmpOpEq, cmp.Op, "ct state != established,related is AND-mask then equal-zero")
			require.Equal(t, binaryutil.NativeEndian.PutUint32(0), cmp.Data)
			require.Equal(t, binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED), v.Mask)
			gotCTEq = true
		case *expr.Immediate:
			if v.Register == 1 {
				gotAddr = v.Data
			}
			if v.Register == 2 {
				gotPort = v.Data
			}
		case *expr.TProxy:
			gotTProxy = v
		}
	}

	require.Equal(t, paddedIfaceName(iface), gotIface)
	require.Equal(t, []byte{proto}, gotProto)
	require.True(t, loadedDst, "missing transport-header dport payload load")
	require.Equal(t, expr.CmpOpNeq, gotSSHOp)
	require.Equal(t, binaryutil.BigEndian.PutUint16(sshPort), gotSSHPort)
	require.True(t, gotCTEq, "missing ct state equal-zero compare")
	require.Equal(t, []byte{127, 0, 0, 1}, gotAddr)
	require.Equal(t, binaryutil.BigEndian.PutUint16(dport), gotPort)
	require.NotNil(t, gotTProxy)
	require.Equal(t, byte(unix.NFPROTO_IPV4), gotTProxy.Family)
	require.Equal(t, uint32(1), gotTProxy.RegAddr)
	require.Equal(t, uint32(2), gotTProxy.RegPort)
}

func TestNFTablesRedirectorApplyMarshal(t *testing.T) {
	var payloads [][]byte
	c, err := nftables.New(nftables.WithTestDial(
		func(req []netlink.Message) ([]netlink.Message, error) {
			for _, msg := range req {
				b, err := msg.MarshalBinary()
				require.NoError(t, err)
				require.NotEmpty(t, b)
				payloads = append(payloads, b)
			}
			return req, nil
		}))
	require.NoError(t, err)

	r := &nftablesRedirector{c: c}
	err = r.Apply(tproxyRedirect{
		Interface: "eth0",
		SSHPort:   22,
		TCPPort:   5000,
		UDPPort:   5001,
	})
	require.NoError(t, err)
	require.NoError(t, r.Flush())

	joined := bytes.Join(payloads, nil)
	require.True(t, bytes.Contains(joined, []byte("glutton\x00")), "marshaled netlink should name table glutton")
	require.True(t, bytes.Contains(joined, []byte("prerouting\x00")), "marshaled netlink should name chain prerouting")
}

func TestNewTProxyRedirector(t *testing.T) {
	r, err := newTProxyRedirector(redirectorIPTables)
	require.NoError(t, err)
	_, ok := r.(*iptablesRedirector)
	require.True(t, ok)

	r, err = newTProxyRedirector("")
	require.NoError(t, err)
	_, ok = r.(*iptablesRedirector)
	require.True(t, ok)

	_, err = newTProxyRedirector("ebpf")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown redirector")
}

func TestNewTProxyRedirectorNFTables(t *testing.T) {
	r, err := newTProxyRedirector(redirectorNFTables)
	if err != nil {
		t.Skipf("nftables connection unavailable: %v", err)
	}
	nr, ok := r.(*nftablesRedirector)
	require.True(t, ok)
	if nr.c != nil {
		require.NoError(t, nr.c.CloseLasting())
	}
}
