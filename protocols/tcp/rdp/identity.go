package rdp

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/spf13/viper"
)

var (
	rdpIdentityOnce sync.Once
	rdpComputer     string
	rdpDomain       string
)

// Identity returns the stable RDP sensor identity: a NetBIOS computer name
// and a domain/workgroup name. Both values are read from viper keys
// rdp.computer_name and rdp.domain_name; when unset, a random WIN-XXXXXXXXXXX
// computer name and "WORKGROUP" are generated once per process.
//
// The same names must appear in both the TLS certificate (CN) and the NTLM
// Challenge TargetInfo so scanners that read the Challenge cannot distinguish
// the sensor from a real Windows host.
func Identity() (computer, domain string) {
	rdpIdentityOnce.Do(func() {
		rdpComputer = viper.GetString("rdp.computer_name")
		if rdpComputer == "" {
			rdpComputer = randomComputerName()
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

func randomComputerName() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// #nosec G404 — computer name is not security-sensitive.
	src := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 11)
	for i := range b {
		b[i] = chars[src.Intn(len(chars))]
	}
	return fmt.Sprintf("WIN-%s", b)
}
