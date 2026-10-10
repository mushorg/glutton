package helpers

import "bytes"

// ShellcodeResult is the outcome of a heuristic scan for executable payloads
// (x86/x64 shellcode stubs and embedded PE images). It is advisory: a non-zero
// score flags bytes worth a closer look, not a confirmed exploit.
type ShellcodeResult struct {
	Score      int      // sum of the matched indicator weights
	Indicators []string // names of the heuristics that matched, in scan order
}

// shellcodeSig is one static heuristic: a byte pattern and the weight it adds
// when present anywhere in the scanned buffer.
type shellcodeSig struct {
	name    string
	weight  int
	pattern []byte
}

// shellcodeSigs are byte patterns common to Windows shellcode and droppers.
// They are deliberately specific so random binary data rarely matches more than
// one; LooksLikeShellcode requires several (or one strong hit) before it reports
// true.
var shellcodeSigs = []shellcodeSig{
	// Embedded PE image (reflective DLL, dropped executable).
	{"pe-dos-stub", 3, []byte("This program cannot be run in DOS mode")},
	{"pe-signature", 2, []byte("PE\x00\x00")},
	// FSTENV GetPC stub used by shikata_ga_nai and many x86 encoders.
	{"fstenv-getpc", 3, []byte{0xd9, 0x74, 0x24, 0xf4}},
	// Metasploit block_api prologues: cld; call <block_api>.
	{"msf-x86-prologue", 3, []byte{0xfc, 0xe8, 0x82, 0x00, 0x00, 0x00}},
	{"msf-x86-prologue-legacy", 3, []byte{0xfc, 0xe8, 0x89, 0x00, 0x00, 0x00}},
	// Metasploit x64 prologue: cld; and rsp, -16.
	{"msf-x64-prologue", 3, []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0}},
	// PEB walk via the FS/GS segment (resolve kernel32 base).
	{"peb-walk-x86", 2, []byte{0x64, 0xa1, 0x30, 0x00, 0x00, 0x00}}, // mov eax, fs:[30h]
	{"peb-walk-x64", 2, []byte{0x65, 0x48, 0x8b}},                   // mov r64, gs:[..]
}

const (
	// minNOPSled is the shortest run of 0x90 bytes reported as a NOP sled.
	minNOPSled = 16
	// shellcodeThreshold is the score at or above which LooksLikeShellcode
	// reports true.
	shellcodeThreshold = 4
)

// DetectShellcode scans data for the indicators above and returns the matched
// names and their summed weight.
func DetectShellcode(data []byte) ShellcodeResult {
	var res ShellcodeResult
	for _, sig := range shellcodeSigs {
		if bytes.Contains(data, sig.pattern) {
			res.Score += sig.weight
			res.Indicators = append(res.Indicators, sig.name)
		}
	}
	if hasNOPSled(data, minNOPSled) {
		res.Score += 2
		res.Indicators = append(res.Indicators, "nop-sled")
	}
	if hasCallPopGetPC(data) {
		res.Score += 2
		res.Indicators = append(res.Indicators, "call-pop-getpc")
	}
	return res
}

// LooksLikeShellcode reports whether data reaches the shellcode score threshold.
func LooksLikeShellcode(data []byte) bool {
	return DetectShellcode(data).Score >= shellcodeThreshold
}

// hasNOPSled reports whether data contains a run of at least n 0x90 bytes.
func hasNOPSled(data []byte, n int) bool {
	run := 0
	for _, b := range data {
		if b == 0x90 {
			run++
			if run >= n {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

// hasCallPopGetPC matches the "call $+5; pop reg" GetPC stub: E8 00 00 00 00
// followed by a single-byte pop of a 32-bit register (58..5F).
func hasCallPopGetPC(data []byte) bool {
	pat := []byte{0xe8, 0x00, 0x00, 0x00, 0x00}
	for i := 0; i < len(data); {
		j := bytes.Index(data[i:], pat)
		if j < 0 {
			return false
		}
		k := i + j + len(pat)
		if k < len(data) && data[k] >= 0x58 && data[k] <= 0x5f {
			return true
		}
		i += j + 1
	}
	return false
}
