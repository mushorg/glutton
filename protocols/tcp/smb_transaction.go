package tcp

import (
	"encoding/binary"

	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/tcp/smb"
)

// txKind distinguishes how a reassembled transaction payload should be handled
// once complete.
type txKind int

const (
	txNtTransact   txKind = iota // NT_TRANSACT overflow data, captured as-is
	txDoublePulsar               // TRANS2 SESSION_SETUP data, XOR-obfuscated
)

// smbTx reassembles one transaction payload that arrives in a primary request
// and any number of *_SECONDARY fragments. The zero value is "no transaction".
type smbTx struct {
	kind  txKind
	open  bool   // more fragments expected; secondaries get a reply only once it completes
	total uint32 // TotalDataCount claimed by the primary request
	buf   []byte // reassembly buffer, nil when the payload is not captured
	event int    // read frame tagged with the capture results

	// DoublePulsar only.
	opcode   byte   // opcode of the transaction
	paramKey uint32 // key the operator embedded in the exec parameters
	paramSet bool
}

// transaction answers a plain SMB_COM_TRANSACTION.
func (ss *smbServer) transaction(req *smb1Request) error {
	return ss.reply(smb.MakeComTransactionResponse(req.header))
}

// transaction2 answers TRANS2. SESSION_SETUP is where DoublePulsar lives, so
// it is handed to the DoublePulsar emulation first.
func (ss *smbServer) transaction2(req *smb1Request) error {
	setup, setupOK := smb.Trans2Setup(req.body)
	if setupOK && setup == smb.Trans2SessionSetup {
		if handled, err := ss.doublePulsar(req); handled {
			return err
		}
	}
	return ss.reply(smb.MakeComTransaction2Reply(req.header, setup, setupOK))
}

// ntTransact answers NT_TRANSACT and starts capturing its data. EternalBlue
// overflows the server through oversized NT_TRANSACT data split across
// secondaries.
func (ss *smbServer) ntTransact(req *smb1Request) error {
	header, resp, err := smb.MakeComNtTransactionResponse(req.header)
	ss.flushTx()
	total := req.read(ss).TotalDataCount
	ss.tx = smbTx{kind: txNtTransact, open: total > 0, total: total, event: req.readIdx}
	if ss.tx.open && total <= maxSMBTxBuffer && !req.frame.truncated {
		ss.tx.buf = make([]byte, total)
		copy(ss.tx.buf, smb.NtTransactData(req.pdu))
	}
	return ss.reply(header, resp, err)
}

// transactionSecondary appends a *_SECONDARY fragment to the open transaction.
// Middle fragments get no reply; the final one flushes the capture and is
// answered.
func (ss *smbServer) transactionSecondary(req *smb1Request) error {
	cmd := req.header.Command
	disp, count, ok := smb.SecondaryDataRange(cmd, req.body)
	tx := &ss.tx
	if tx.open && tx.buf != nil && !req.frame.truncated {
		if d, data, dok := smb.SecondaryData(cmd, req.pdu); dok && uint64(d)+uint64(len(data)) <= uint64(len(tx.buf)) {
			copy(tx.buf[d:], data)
		}
	}
	if !tx.open || !ok || uint64(disp)+uint64(count) < uint64(tx.total) {
		return nil // middle fragment: no reply
	}
	dpExec := tx.kind == txDoublePulsar && tx.opcode == smb.DPOpExec && ss.variant == smb.Infected
	ss.flushTx()
	if dpExec {
		return ss.replyDP(smb.MakeDoublePulsarExecResponse(req.header))
	}
	return ss.reply(smb.MakeTransactionCompleteResponse(req.header))
}

// beginDoublePulsar starts reassembling a DoublePulsar TRANS2 SESSION_SETUP
// payload. The data arrives XOR-obfuscated, in the initial request and (for
// larger payloads) across TRANSACTION2_SECONDARY fragments. It is stored and
// decoded by flushTx once the final fragment lands, or at connection end.
func (ss *smbServer) beginDoublePulsar(req *smb1Request, op byte) {
	ss.flushTx() // flush any prior transaction first
	total := req.read(ss).TotalDataCount
	ss.tx = smbTx{kind: txDoublePulsar, total: total, event: req.readIdx, opcode: op}
	if p := smb.Trans2Parameters(req.pdu); len(p) >= 4 {
		ss.tx.paramKey, ss.tx.paramSet = binary.LittleEndian.Uint32(p[len(p)-4:]), true
	}
	if total == 0 || total > maxSMBTxBuffer || req.frame.truncated {
		return
	}
	ss.tx.buf = make([]byte, total)
	if n := copy(ss.tx.buf, smb.Trans2Data(req.pdu)); uint32(n) >= total {
		ss.flushTx() // single-fragment payload: complete now
		return
	}
	ss.tx.open = true
}

// flushTx closes the current transaction, stores the reassembled data, and
// tags the read frame that started it with the content hash. NT_TRANSACT
// overflow data (EternalBlue) is stored as seen; TRANS2 SESSION_SETUP data
// (DoublePulsar) is also XOR-recovered and the de-obfuscated payload stored
// alongside it. Either way the captured bytes are scanned for shellcode.
func (ss *smbServer) flushTx() {
	tx := ss.tx
	ss.tx = smbTx{}
	if len(tx.buf) == 0 {
		return
	}
	if _, ok := ss.storePayload(tx.buf, "SMB transaction payload"); !ok {
		return
	}
	ev := ss.event(tx.event)
	if ev == nil {
		return
	}
	ev.PayloadHash = helpers.SHA256Hex(tx.buf)
	if res := helpers.DetectShellcode(tx.buf); len(res.Indicators) > 0 {
		ev.Shellcode = res.Indicators
	}
	if tx.kind == txDoublePulsar {
		ss.decodeDoublePulsar(tx, ev)
	}
}
