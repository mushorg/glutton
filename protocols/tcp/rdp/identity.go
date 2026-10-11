package rdp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/spf13/viper"
)

var (
	rdpIdentityOnce sync.Once
	rdpComputer     string
	rdpDomain       string
)

// Identity returns the stable RDP sensor identity: a NetBIOS computer name
// and a domain/workgroup name. Both values are read from viper keys
// rdp.computer_name and rdp.domain_name; when unset, "WORKGROUP" and a random
// WIN-XXXXXXXXXXX computer name are used. The generated name is persisted in
// <var-dir>/rdp_computer_name, so it is unique per sensor and survives
// restarts. Without a writable var-dir it is random per process.
//
// The same names must appear in both the TLS certificate (CN) and the NTLM
// Challenge TargetInfo so scanners that read the Challenge cannot distinguish
// the sensor from a real Windows host.
func Identity() (computer, domain string) {
	rdpIdentityOnce.Do(func() {
		rdpComputer = viper.GetString("rdp.computer_name")
		if rdpComputer == "" {
			rdpComputer = persistedComputerName(viper.GetString("var-dir"))
		}
		rdpDomain = viper.GetString("rdp.domain_name")
		if rdpDomain == "" {
			rdpDomain = "WORKGROUP"
		}
	})
	return rdpComputer, rdpDomain
}

// resetIdentity resets the cached identity. Tests that need a fresh identity
// must call this before (and after) manipulating viper keys.
func resetIdentity() {
	rdpIdentityOnce = sync.Once{}
	rdpComputer = ""
	rdpDomain = ""
}

var computerNameRE = regexp.MustCompile(`^WIN-[A-Z0-9]{11}$`)

// persistedComputerName loads the generated computer name from dir, creating
// and saving a new one on first use. An empty dir skips persistence.
func persistedComputerName(dir string) string {
	if dir == "" {
		return randomComputerName()
	}
	path := filepath.Join(dir, "rdp_computer_name")
	if b, err := os.ReadFile(path); err == nil && computerNameRE.Match(b) {
		return string(b)
	}
	name := randomComputerName()
	if err := os.MkdirAll(dir, 0o755); err == nil {
		_ = os.WriteFile(path, []byte(name), 0o644)
	}
	return name
}

func randomComputerName() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 11)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			panic(err)
		}
		b[i] = chars[n.Int64()]
	}
	return fmt.Sprintf("WIN-%s", b)
}
