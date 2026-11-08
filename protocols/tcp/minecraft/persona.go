package minecraft

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
	// Open accepts offline-mode logins instead of answering not_whitelisted;
	// the session then runs through Configuration into Play. Only
	// PlayProtocol is implemented, so an Open persona must speak it.
	Open bool
}

// Personas is the rotation order for returning sources. The first is an
// untouched default server, so a first visit sees what it always saw. The
// others are small servers with a few friends online. Each runs its own
// version, as servers in the wild do: a freshly updated offline-mode Fabric
// SMP with an auth mod that lets anyone in and asks them to /register, and a
// whitelisted survival server pinned to the long-lived 1.21.1 modding release.
var Personas = []Persona{
	{Name: "default", Version: DefaultVersionName, Protocol: DefaultProtocol, MOTD: "A Minecraft Server", Max: 20},
	{Name: "smp", Version: "1.21.8", Protocol: PlayProtocol, MOTD: "Friends SMP", Max: 10, Players: []string{"kuba_mc", "Nyxie"}, Open: true},
	{Name: "survival", Version: "1.21.1", Protocol: 767, MOTD: "survival server - whitelist only", Max: 20, Players: []string{"dragonslayer07"}},
}

// OfflineUUID returns the UUID an offline-mode server gives name: a
// version 3 UUID of "OfflinePlayer:"+name, as Java's UUID.nameUUIDFromBytes.
func OfflineUUID(name string) string {
	b := offlineUUIDBytes(name)
	return formatUUID(b[:])
}
