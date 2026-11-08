package ssh

import (
	"strconv"
	"strings"
)

// FleetAuthKeysImplant is the scanner label of a session that planted a key in
// an authorized_keys file. It is behavioral, not an attribution: many bots run
// the same one-liner (cd ~ && mkdir -p .ssh && echo "ssh-rsa ..." >> authorized_keys).
const FleetAuthKeysImplant = "ssh-authkeys-implant"

// FleetSpoofedOpenSSH is the scanner label of a client whose identification
// string claims OpenSSH while its KEXINIT could not come from OpenSSH (see
// SpoofedOpenSSH). Scanners built on other SSH libraries send an OpenSSH
// banner to blend in.
const FleetSpoofedOpenSSH = "ssh-spoofed-openssh"

// IsAuthorizedKeys reports whether path is a user's authorized_keys file.
func IsAuthorizedKeys(path string) bool {
	for _, name := range []string{"authorized_keys", "authorized_keys2"} {
		if strings.HasSuffix(path, "/.ssh/"+name) {
			return true
		}
	}
	return false
}

// removedIn76 are the ciphers and MACs OpenSSH 7.6 deleted: a client claiming
// 7.6 or later cannot offer them, whatever its configuration.
var removedIn76 = map[string]bool{
	"arcfour": true, "arcfour128": true, "arcfour256": true,
	"blowfish-cbc": true, "cast128-cbc": true,
	"hmac-ripemd160": true, "hmac-ripemd160@openssh.com": true,
	"hmac-ripemd160-etm@openssh.com": true,
}

// SpoofedOpenSSH reports whether a client identification string (as framed,
// without CR LF) claims OpenSSH while its KEXINIT contradicts it: an
// algorithm repeated within one name-list (OpenSSH never repeats one), or a
// cipher or MAC removed in OpenSSH 7.6 offered by a client claiming 7.6 or
// later.
func SpoofedOpenSSH(version string, k *KexInit) bool {
	if k == nil {
		return false
	}
	major, minor, ok := openSSHVersion(version)
	if !ok {
		return false
	}
	lists := [][]string{
		k.KexAlgos, k.ServerHostKeyAlgos,
		k.CiphersClientServer, k.CiphersServerClient,
		k.MACsClientServer, k.MACsServerClient,
		k.CompressionClientServer, k.CompressionServerClient,
	}
	modern := major > 7 || (major == 7 && minor >= 6)
	for _, l := range lists {
		seen := make(map[string]bool, len(l))
		for _, name := range l {
			if seen[name] || (modern && removedIn76[name]) {
				return true
			}
			seen[name] = true
		}
	}
	return false
}

// openSSHVersion returns the release of an "SSH-2.0-OpenSSH_9.2p1 ..."
// identification string.
func openSSHVersion(version string) (major, minor int, ok bool) {
	_, software, found := strings.Cut(version, "-")
	if !found {
		return 0, 0, false
	}
	// skip the protoversion
	if _, software, found = strings.Cut(software, "-"); !found {
		return 0, 0, false
	}
	release, found := strings.CutPrefix(software, "OpenSSH_")
	if !found {
		return 0, 0, false
	}
	majorStr, rest, found := strings.Cut(release, ".")
	if !found {
		return 0, 0, false
	}
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	var err error
	if major, err = strconv.Atoi(majorStr); err != nil {
		return 0, 0, false
	}
	if minor, err = strconv.Atoi(rest[:end]); err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
