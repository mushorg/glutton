# Getting started

Glutton is a Go-based, multi-protocol honeypot. It uses Linux iptables and TPROXY to transparently redirect TCP and UDP traffic to local listeners, dispatches connections through a BPF-style rule engine, runs protocol-specific handlers (or forwards to an upstream via `proxy_tcp`, or falls back to generic capture), and writes structured JSON logs and optional producer events.

## Spicy

Glutton also includes an emerging Spicy parser path. Spicy is the parser-definition language from the Zeek project; it lets contributors describe byte-level protocol grammars in a small DSL instead of writing the parser in Go. Currently Glutton uses Spicy for HTTP parsing and TCP-payload protocol detection only.

## Requirements

Glutton is a Linux-only Go binary that depends on iptables, libpcap, a C/C++ toolchain, and Spicy/HILTI. Treat it as hostile-facing infrastructure once it's running: it receives unsolicited traffic, records attacker-controlled payloads, and manages network redirection rules.

| Requirement                     | Source of truth                                                                                                          |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Go 1.23+                        | `go.mod` declares `go 1.23.5`; CI uses `^1.23`.                                                                          |
| libpcap                         | Required by `github.com/google/gopacket/pcap`.                                                                           |
| iptables                        | TPROXY rule management.                                                                                                  |
| zlib + build-essential          | Spicy and cgo builds.                                                                                                    |
| clang / clang++                 | `Makefile` uses `CC=clang CXX=clang++`; CI installs clang 17.                                                            |
| Spicy 1.13.1 under `/opt/spicy` | The cgo flags in `protocols/spicy/parser.go` expect headers under `/opt/spicy/include` and libraries under `/opt/spicy/lib`. |

## Build

CI runs on Ubuntu. Other distros need equivalent packages.

```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev iptables zlib1g-dev build-essential clang

wget https://github.com/zeek/spicy/releases/download/v1.13.1/spicy_linux_ubuntu24.deb
sudo dpkg --install spicy_linux_ubuntu24.deb
sudo apt-get install -f -y
rm spicy_linux_ubuntu24.deb

git clone https://github.com/mushorg/glutton.git
cd glutton
export PATH=/opt/spicy/bin:$PATH
make spicy
make build
```

`make spicy` runs the Spicy Makefile under `protocols/spicy/` to generate parser C++ and headers (gitignored). `make build` compiles `app/server.go` into `bin/server` with embedded version metadata.

## Run

Glutton modifies iptables rules and needs root (or `CAP_NET_ADMIN`).

```bash
sudo bin/server --interface eth0 --confpath config/ --logpath /var/log/glutton.log
```

For Docker, mount or build the config you intend to run, and use the host network namespace so TPROXY rules apply to a real interface:

```bash
docker build -t glutton .
docker run --rm --network host --cap-add=NET_ADMIN -it glutton
```

Without `--network host` the container installs TPROXY rules on the docker bridge and never sees external traffic. The host kernel must have iptables `mangle` and `xt_TPROXY` available.

### Verify

```bash
bin/server --version
```

Prints the banner and version string and exits without initializing the runtime. Useful for confirming a build picked up the expected `Makefile` version metadata.

## Privileges

Glutton needs permission to:

- read from TPROXY sockets
- add and remove iptables mangle PREROUTING rules
- bind local TCP and UDP listener ports
- write its sensor ID under `--var-dir` (default `/var/lib/glutton`)
- write the configured log file

`sudo` on bare metal or `--cap-add=NET_ADMIN` in Docker satisfies all of these.

## Host placement

- Run on a dedicated host, VM, or isolated network segment. Not a workstation, not anything with internal access.
- Restrict outbound egress unless a handler or producer needs it. `proxy_tcp` rules open outbound connections to whatever upstream the rule targets — keep that surface explicit.
- Keep producer endpoints (HTTP collector, hpfeeds broker) off the exposed honeypot network.
- Rotate and ship logs before disk pressure becomes operational risk.

Glutton is a sensor, not a containment boundary. Use network isolation around it.

## Operational hazards

- iptables state can be left behind if the process is killed without a clean shutdown.
- Captured payloads are attacker-controlled. Handle them as untrusted in any downstream pipeline.
- Some handlers send fake service responses. Don't route real internal clients through the sensor.
- Legal and privacy obligations vary by jurisdiction. Get local review before collecting or sharing payloads.
