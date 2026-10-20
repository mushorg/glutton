package ssh

import "strings"

// FleetAuthKeysImplant is the scanner label of a session that planted a key in
// an authorized_keys file. It is behavioral, not an attribution: many bots run
// the same one-liner (cd ~ && mkdir -p .ssh && echo "ssh-rsa ..." >> authorized_keys).
const FleetAuthKeysImplant = "ssh-authkeys-implant"

// IsAuthorizedKeys reports whether path is a user's authorized_keys file.
func IsAuthorizedKeys(path string) bool {
	for _, name := range []string{"authorized_keys", "authorized_keys2"} {
		if strings.HasSuffix(path, "/.ssh/"+name) {
			return true
		}
	}
	return false
}
