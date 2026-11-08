package minecraft

import (
	"crypto/md5"
	"fmt"
)

// Persona is the server a Status Response advertises: its game version, its
// server.properties MOTD and max-players, and the players currently online.
// Only 1.20.5+ versions fit: older servers encode the status JSON differently
// (object MOTD, explicit defaults).
type Persona struct {
	// Name labels the persona in decoded frames and recall summaries.
	Name     string
	Version  string // version name, e.g. "1.21.4"
	Protocol int32  // protocol number matching Version
	MOTD     string
	Max      int
	Players  []string
}

// Personas is the rotation order for returning sources. The first is an
// untouched default server, so a first visit sees what it always saw. The
// others are small whitelisted servers with a few friends online, which fits
// the not_whitelisted login Disconnect. Each runs its own version, as servers
// in the wild do: a freshly updated SMP and a survival server pinned to the
// long-lived 1.21.1 modding release.
var Personas = []Persona{
	{Name: "default", Version: DefaultVersionName, Protocol: DefaultProtocol, MOTD: "A Minecraft Server", Max: 20},
	{Name: "smp", Version: "1.21.8", Protocol: 772, MOTD: "Friends SMP", Max: 10, Players: []string{"kuba_mc", "Nyxie"}},
	{Name: "survival", Version: "1.21.1", Protocol: 767, MOTD: "survival server - whitelist only", Max: 20, Players: []string{"dragonslayer07"}},
}

// OfflineUUID returns the UUID an offline-mode server gives name: a
// version 3 UUID of "OfflinePlayer:"+name, as Java's UUID.nameUUIDFromBytes.
func OfflineUUID(name string) string {
	b := md5.Sum([]byte("OfflinePlayer:" + name))
	b[6] = b[6]&0x0f | 0x30
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
