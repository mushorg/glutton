package tcp

import (
	"encoding/binary"
	"fmt"

	"github.com/mushorg/glutton/protocols/helpers"
	"github.com/mushorg/glutton/protocols/tcp/smb"
)

const (
	// dpProbeLen bounds how many leading bytes the XOR-key search inspects. The
	// DoublePulsar key repeats every 4 bytes, so a prefix is enough to find it.
	dpProbeLen = 1024
	// dpMinScore is the shellcode score a decoded probe must reach for the
	// recovered key to be accepted, keeping false positives from the 64K-seed
	// brute force low.
	dpMinScore = 3
	// dpGoodScore stops the search early once a key decodes to an obviously
	// executable payload.
	dpGoodScore = 6
)

func dpOpName(op byte) string {
	switch op {
	case smb.DPOpPing:
		return "doublepulsar_ping"
	case smb.DPOpExec:
		return "doublepulsar_exec"
	case smb.DPOpKill:
		return "doublepulsar_kill"
	}
	return ""
}

// doublePulsar handles a TRANS2 SESSION_SETUP, which DoublePulsar uses as its
// command channel: the opcode is encoded in the Timeout field and the
// (XOR-obfuscated) payload is split across TRANS2 SESSION_SETUP +
// TRANSACTION2_SECONDARY fragments. The payload is captured regardless of the
// variant; only the smb.Infected variant answers as an implanted host. It
// reports whether it wrote the reply.
func (ss *smbServer) doublePulsar(req *smb1Request) (bool, error) {
	op := smb.DoublePulsarOpcode(smb.Trans2Timeout(req.body))
	if name := dpOpName(op); name != "" {
		ss.dpOps = append(ss.dpOps, name)
	}
	if req.read(ss).TotalDataCount > 0 {
		ss.beginDoublePulsar(req, op)
	}
	if ss.variant != smb.Infected {
		return false, nil
	}
	switch {
	case op == smb.DPOpPing:
		var sig [8]byte
		_, _ = smbReadRand(sig[:])
		s := binary.LittleEndian.Uint64(sig[:])
		ss.dpKey, ss.dpKeySet, ss.dpArchX64 = smb.DoublePulsarXORKey64(s), true, smb.DoublePulsarArchX64(s)
		return true, ss.replyDP(smb.MakeDoublePulsarPingResponse(req.header, sig))
	case op == smb.DPOpExec && !ss.tx.open:
		// Multi-fragment exec payloads are answered on the final secondary.
		return true, ss.replyDP(smb.MakeDoublePulsarExecResponse(req.header))
	case op == smb.DPOpKill:
		ss.dpKeySet = false
		return true, ss.replyDP(smb.MakeDoublePulsarKillResponse(req.header))
	}
	return false, nil
}

// replyDP sends a DoublePulsar emulation reply and stamps its frame with the
// variant and visit.
func (ss *smbServer) replyDP(header smb.SMBHeader, resp []byte, err error) error {
	if err := ss.reply(header, resp, err); err != nil {
		return err
	}
	ev := &ss.events[len(ss.events)-1]
	ev.Variant = ss.variant.String()
	ev.Visit = ss.visit
	return nil
}

// decodeDoublePulsar recovers the XOR key of a captured DoublePulsar payload,
// stores the de-obfuscated bytes, and records the key and decoded hash on ev.
func (ss *smbServer) decodeDoublePulsar(tx smbTx, ev *parsedSMB) {
	key, plain, ok := ss.doublePulsarKey(tx)
	if !ok {
		return
	}
	ev.XORKey = fmt.Sprintf("%08x", key)
	if dh, ok := ss.storePayload(plain, "decoded DoublePulsar payload"); ok {
		ev.DecodedHash = dh
	}
	if res := helpers.DetectShellcode(plain); len(res.Indicators) > 0 {
		ev.Shellcode = res.Indicators
	}
}

// doublePulsarKey finds the XOR key for a captured payload, cheapest source
// first: the key implied by the signature we sent in a ping reply, then the key
// the operator embedded in the exec parameters, then a brute force.
func (ss *smbServer) doublePulsarKey(tx smbTx) (key uint32, plain []byte, ok bool) {
	if ss.dpKeySet {
		// We chose the signature in the ping reply, so the key is known.
		return ss.dpKey, smb.XORApply(tx.buf, ss.dpKey), true
	}
	if tx.paramSet {
		probe := tx.buf[:min(len(tx.buf), dpProbeLen)]
		if helpers.DetectShellcode(smb.XORApply(probe, tx.paramKey)).Score >= dpMinScore {
			return tx.paramKey, smb.XORApply(tx.buf, tx.paramKey), true
		}
	}
	return recoverDoublePulsarXOR(tx.buf)
}

// recoverDoublePulsarXOR brute-forces the DoublePulsar XOR key over every
// signature seed and keeps the one whose plaintext looks most like an executable
// payload. It returns the recovered key and the fully de-obfuscated buffer, or
// ok=false when no seed produces a convincing decode.
func recoverDoublePulsarXOR(buf []byte) (key uint32, plain []byte, ok bool) {
	probe := buf[:min(len(buf), dpProbeLen)]
	scratch := make([]byte, len(probe))
	bestScore := 0
	var bestKey uint32
	for s := 0; s <= 0xffff; s++ {
		candidate := smb.DoublePulsarXORKey(uint32(s))
		smb.XORInto(scratch, probe, candidate)
		if res := helpers.DetectShellcode(scratch); res.Score > bestScore {
			bestScore = res.Score
			bestKey = candidate
			if bestScore >= dpGoodScore {
				break
			}
		}
	}
	if bestScore < dpMinScore {
		return 0, nil, false
	}
	return bestKey, smb.XORApply(buf, bestKey), true
}
