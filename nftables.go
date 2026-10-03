package glutton

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	nftablesTableName = "glutton"
	nftablesChainName = "prerouting"
)

var tproxyIPv4 = net.IPv4(127, 0, 0, 1).To4()

type nftablesRedirector struct {
	c *nftables.Conn
}

func newNFTablesRedirector() (*nftablesRedirector, error) {
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("failed to create nftables connection: %w", err)
	}
	return &nftablesRedirector{c: c}, nil
}

func gluttonNFTable() *nftables.Table {
	return &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftablesTableName,
	}
}

func paddedIfaceName(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name+"\x00")
	return b
}

// tproxyRuleExprs builds the nftables match+TPROXY expression list equivalent to:
// iifname <iface> <tcp|udp> dport != <ssh> ct state != established,related tproxy to 127.0.0.1:<port>
func tproxyRuleExprs(iface string, proto uint8, sshPort, dport uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: paddedIfaceName(iface)},

		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},

		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.BigEndian.PutUint16(sshPort)},

		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},

		&expr.Immediate{Register: 1, Data: tproxyIPv4},
		&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(dport)},
		&expr.TProxy{
			Family:      unix.NFPROTO_IPV4,
			TableFamily: unix.NFPROTO_IPV4,
			RegAddr:     1,
			RegPort:     2,
		},
	}
}

func (r *nftablesRedirector) Apply(cfg tproxyRedirect) error {
	if r.c == nil {
		return errors.New("nil nftables connection")
	}

	table := gluttonNFTable()
	// Drop a leftover table from an unclean shutdown before recreating it.
	r.c.DelTable(table)
	_ = r.c.Flush()

	policy := nftables.ChainPolicyAccept
	table = r.c.AddTable(table)
	chain := r.c.AddChain(&nftables.Chain{
		Name:     nftablesChainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
		Policy:   &policy,
	})

	r.c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: tproxyRuleExprs(cfg.Interface, unix.IPPROTO_TCP, cfg.SSHPort, cfg.TCPPort),
	})
	r.c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: tproxyRuleExprs(cfg.Interface, unix.IPPROTO_UDP, cfg.SSHPort, cfg.UDPPort),
	})

	if err := r.c.Flush(); err != nil {
		return fmt.Errorf("failed to set TPROXY nftables rules: %w", err)
	}
	return nil
}

func (r *nftablesRedirector) Flush() error {
	if r.c == nil {
		return nil
	}
	r.c.DelTable(gluttonNFTable())
	err := r.c.Flush()
	return errors.Join(err, r.c.CloseLasting())
}
