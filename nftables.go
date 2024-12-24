package glutton

import (
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func makeNFTablesRule(port uint16, protocol int) *nftables.Rule {
	return &nftables.Rule{
		Table: &nftables.Table{Name: "filter", Family: nftables.TableFamilyIPv4},
		Chain: &nftables.Chain{
			Name:     "divert",
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityRef(-150),
		},
		Exprs: []expr.Any{
			//	[ payload load 1b @ network header + 9 => reg 1 ] this is the protocol field
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			//	[ cmp eq reg 1 0x00000006 ] this is the protocol value for TCP (6)
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(protocol)}},
			//	[ immediate reg 1 0x7F000001 ] this is destination ip 127.0.0.1
			&expr.Immediate{Register: 1, Data: []byte("\x7F\x00\x00\x01")},
			//	[ immediate reg 2 0x1388 ] this is destination port
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(port)},
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

func setTProxyNFTables(c *nftables.Conn, port uint16, protocol int) error {
	rule := c.AddRule(makeNFTablesRule(port, protocol))

	if err := c.Flush(); err != nil {
		return err
	}

	rule.Handle = uint64(9)
	if err := c.DelRule(rule); err != nil {
		return err
	}

	return c.Flush()
}
