package glutton

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// nft add rule filter divert tcp dport 80 tproxy to :50080 meta mark set 1 accept
func setTProxy(port uint32) error {
	c := &nftables.Conn{}

	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "filter",
	}

	table = c.AddTable(table)

	chain := c.AddChain(&nftables.Chain{
		Name:     "divert",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	// -tcp --dport 0:65534 --sport 0:65534
	//tcpMatch := &expr.Match{
	//	Name: "tcp",
	//	Info: &xt.Tcp{
	//		SrcPorts: [2]uint16{0, 65534},
	//		DstPorts: [2]uint16{0, 65534},
	//		//DstPorts: [2]uint16{80, 80},
	//	},
	//}

	//tproxy := &expr.TProxy{
	//	Family:      byte(nftables.TableFamilyIPv4),
	//	TableFamily: byte(nftables.TableFamilyIPv4),
	//	RegPort:     1,
	//}

	metaMark := &expr.Meta{
		Key:            expr.MetaKeyMARK,
		SourceRegister: true,
		Register:       1,
	}

	accept := &expr.Verdict{
		Kind: expr.VerdictAccept,
	}

	r := &nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			//tcpMatch,
			//tproxy,
			&expr.TProxy{
				Family:      byte(nftables.TableFamilyIPv4),
				TableFamily: byte(nftables.TableFamilyIPv4),
				RegPort:     1,
			},
			metaMark,
			accept,
		},
	}
	c.AddRule(r)

	return c.Flush()
}
