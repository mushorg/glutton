package glutton

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func makeNFTablesRule(dport, sshPort uint16, protocol int, iface string) *nftables.Rule {
	return &nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name:     "divert",
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityRef(-150),
		},
		Exprs: []expr.Any{
			// Match incoming interface
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(iface)},
			//	[ payload load 1b @ network header + 9 => reg 1 ] this is the protocol field
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			//	[ cmp eq reg 1 0x00000006 ] this is the protocol value for TCP (6)
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(protocol)}},
			// Compare destination port not equal to 22
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 2, Data: binaryutil.BigEndian.PutUint16(sshPort)},
			// Match connection state
			&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
			// Compare connection state not equal to ESTABLISHED or RELATED
			&expr.Bitwise{
				DestRegister:   1,
				SourceRegister: 1,
				Len:            4,
				Mask:           []byte{0x06, 0x00, 0x00, 0x00}, // ESTABLISHED and RELATED states
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x06, 0x00, 0x00, 0x00}},
			//	[ immediate reg 1 0x7F000001 ] this is destination ip 127.0.0.1
			&expr.Immediate{Register: 1, Data: []byte("\x7F\x00\x00\x01")},
			//	[ immediate reg 2 0x1388 ] this is destination port
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(dport)},
			//	[ tproxy ip addr reg 1 port reg 2 ]
			&expr.TProxy{
				Family:      byte(nftables.TableFamilyIPv4),
				TableFamily: byte(nftables.TableFamilyIPv4),
				RegAddr:     1,
				RegPort:     2,
			},
		},
	}
}

func newCon() (*nftables.Conn, error) {
	return nftables.New(nftables.AsLasting())
}

func setTProxyNFTables(c *nftables.Conn, dport, sshPort uint16, protocol int, iface string) (*nftables.Rule, error) {
	rule := c.AddRule(makeNFTablesRule(dport, sshPort, protocol, iface))

	if err := c.Flush(); err != nil {
		return rule, fmt.Errorf("failed to set TPROXY nftables rule: %v", err)
	}

	rule.Handle = uint64(9)
	if err := c.DelRule(rule); err != nil {
		return rule, err
	}

	return rule, c.Flush()
}

func deleteTProxyNFTables(c *nftables.Conn, r []*nftables.Rule) error {
	for _, rule := range r {
		if err := c.DelRule(rule); err != nil {
			return err
		}
	}
	return c.Flush()
}
