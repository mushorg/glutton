package ssh

// Persona is the system the honeypot pretends to be: the identification
// string a scanner fingerprints and the facts the fake shell reports. The key
// exchange, cipher and MAC lists are fixed by golang.org/x/crypto/ssh, so a
// persona changes the banner and the shell, not the HASSH.
type Persona struct {
	Name     string // stable key, recorded as the variant of the banner frame
	Version  string // identification string, without CR LF
	Hostname string
	Pretty   string // PRETTY_NAME of /etc/os-release
	ID       string // ID of /etc/os-release
	Release  string // VERSION_ID of /etc/os-release
	Kernel   string // uname -r
	Build    string // uname -v
	CPU      string // model name in /proc/cpuinfo
	Cores    int
}

// Personas lists the available systems. The first one is the original
// persona and the banner the catch-all uses. Every persona must be an OpenSSH
// that ships strict key exchange (the distributions backported it to the
// versions listed), because x/crypto always offers kex-strict-s-v00@openssh.com:
// an older persona such as CentOS 7's OpenSSH 7.4 would contradict its own
// KEXINIT.
var Personas = []Persona{
	{
		Name: "ubuntu-22.04", Version: ServerVersion, Hostname: "ubuntu",
		Pretty: "Ubuntu 22.04.4 LTS", ID: "ubuntu", Release: "22.04",
		Kernel: "5.15.0-107-generic", Build: "#117-Ubuntu SMP Fri Apr 26 12:26:49 UTC 2024",
		CPU: "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", Cores: 4,
	},
	{
		Name: "ubuntu-20.04", Version: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11", Hostname: "web-prod-02",
		Pretty: "Ubuntu 20.04.6 LTS", ID: "ubuntu", Release: "20.04",
		Kernel: "5.4.0-182-generic", Build: "#202-Ubuntu SMP Fri Apr 26 12:29:36 UTC 2024",
		CPU: "Intel(R) Xeon(R) Gold 6148 CPU @ 2.40GHz", Cores: 2,
	},
	{
		Name: "ubuntu-24.04", Version: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", Hostname: "vps-4821",
		Pretty: "Ubuntu 24.04 LTS", ID: "ubuntu", Release: "24.04",
		Kernel: "6.8.0-45-generic", Build: "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024",
		CPU: "AMD EPYC 7543 32-Core Processor", Cores: 2,
	},
	{
		Name: "debian-12", Version: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3", Hostname: "debian",
		Pretty: "Debian GNU/Linux 12 (bookworm)", ID: "debian", Release: "12",
		Kernel: "6.1.0-23-amd64", Build: "#1 SMP PREEMPT_DYNAMIC Debian 6.1.99-1 (2024-07-15)",
		CPU: "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz", Cores: 2,
	},
	{
		Name: "debian-11", Version: "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3", Hostname: "db01",
		Pretty: "Debian GNU/Linux 11 (bullseye)", ID: "debian", Release: "11",
		Kernel: "5.10.0-30-amd64", Build: "#1 SMP Debian 5.10.218-1 (2024-06-01)",
		CPU: "Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz", Cores: 8,
	},
}

// PersonaNames returns the persona keys in Personas order.
func PersonaNames() []string {
	names := make([]string, len(Personas))
	for i, p := range Personas {
		names[i] = p.Name
	}
	return names
}

// PersonaByName returns the persona called name.
func PersonaByName(name string) (Persona, bool) {
	for _, p := range Personas {
		if p.Name == name {
			return p, true
		}
	}
	return Persona{}, false
}

// PersonaVersions returns the identification strings of all personas.
func PersonaVersions() []string {
	versions := make([]string, len(Personas))
	for i, p := range Personas {
		versions[i] = p.Version
	}
	return versions
}
