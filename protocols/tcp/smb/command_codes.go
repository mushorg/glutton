package smb

import "fmt"

const (
	CmdTransaction          = 0x25
	CmdTransactionSecondary = 0x26
	CmdTransaction2         = 0x32
	CmdTreeDisconnect       = 0x71
	CmdNegotiate            = 0x72
	CmdSessionSetupAndX     = 0x73
	CmdLogoffAndX           = 0x74
	CmdTreeConnectAndX      = 0x75
	CmdNtTransact           = 0xa0
	CmdNtTransactSecondary  = 0xa1
	CmdNtCreateAndX         = 0xa2
)

var smb1CommandNames = map[byte]string{
	CmdTransaction:          "SMB_COM_TRANSACTION",
	CmdTransactionSecondary: "SMB_COM_TRANSACTION_SECONDARY",
	CmdTransaction2:         "SMB_COM_TRANSACTION2",
	CmdTreeDisconnect:       "SMB_COM_TREE_DISCONNECT",
	CmdNegotiate:            "SMB_COM_NEGOTIATE",
	CmdSessionSetupAndX:     "SMB_COM_SESSION_SETUP_ANDX",
	CmdLogoffAndX:           "SMB_COM_LOGOFF_ANDX",
	CmdTreeConnectAndX:      "SMB_COM_TREE_CONNECT_ANDX",
	CmdNtTransact:           "SMB_COM_NT_TRANSACT",
	CmdNtTransactSecondary:  "SMB_COM_NT_TRANSACT_SECONDARY",
	CmdNtCreateAndX:         "SMB_COM_NT_CREATE_ANDX",
}

// CommandName returns the SMB1 command mnemonic, or SMB_COM_0xNN for unknowns.
func CommandName(cmd byte) string {
	if name, ok := smb1CommandNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("SMB_COM_0x%02X", cmd)
}

const (
	SMB2CmdNegotiate      = 0x0000
	SMB2CmdSessionSetup   = 0x0001
	SMB2CmdLogoff         = 0x0002
	SMB2CmdTreeConnect    = 0x0003
	SMB2CmdTreeDisconnect = 0x0004
)

var smb2CommandNames = map[uint16]string{
	SMB2CmdNegotiate:      "SMB2_NEGOTIATE",
	SMB2CmdSessionSetup:   "SMB2_SESSION_SETUP",
	SMB2CmdLogoff:         "SMB2_LOGOFF",
	SMB2CmdTreeConnect:    "SMB2_TREE_CONNECT",
	SMB2CmdTreeDisconnect: "SMB2_TREE_DISCONNECT",
}

// SMB2CommandName returns the SMB2 command mnemonic, or SMB2_0xNNNN for unknowns.
func SMB2CommandName(cmd uint16) string {
	if name, ok := smb2CommandNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("SMB2_0x%04X", cmd)
}
