package smb

var codes = map[int]string{
	0x25: "SMB_COM_TRANSACTION",        //37
	0x32: "SMB_COM_TRANSACTION2",       //50
	0x72: "SMB_COM_NEGOTIATE",          //114
	0x73: "SMB_COM_SESSION_SETUP_ANDX", //115
	0x75: "SMB_COM_TREE_CONNECT_ANDX",  //117
}
