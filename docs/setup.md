# Setup

Last verified against source on 2026-05-15.

Glutton is a Linux-oriented Go project that depends on iptables, libpcap, C/C++ build tooling, and Spicy/HILTI for the current parser integration.

## Requirements

| Requirement | Source |
| --- | --- |
| Go 1.23.x | `go.mod` declares `go 1.23.5`; CI uses `go-version: "^1.23"`. |
| libpcap | Required by `github.com/google/gopacket/pcap` and installed in CI. |
| iptables | Required for TPROXY rule management. |
| zlib and build-essential tools | Installed in CI for Spicy and cgo builds. |
| clang / clang++ | `Makefile` builds with `CC=clang CXX=clang++`; CI installs clang 17. |
| Spicy 1.13.1 under `/opt/spicy` | CI installs the Zeek Spicy 1.13.1 Ubuntu package and adds `/opt/spicy/bin` to PATH. |

The Spicy cgo flags in `protocols/spicy/parser.go` expect headers under `/opt/spicy/include` and libraries under `/opt/spicy/lib`.

## Debian / Ubuntu

The CI workflow uses Ubuntu and installs these base packages:

```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev iptables zlib1g-dev build-essential
```

Install Spicy/HILTI from the Zeek Spicy release package that matches your distribution. CI currently uses:

```bash
wget https://github.com/zeek/spicy/releases/download/v1.13.1/spicy_linux_ubuntu24.deb
sudo dpkg --install spicy_linux_ubuntu24.deb
sudo apt-get install -f -y
rm spicy_linux_ubuntu24.deb
export PATH=/opt/spicy/bin:$PATH
```

Install clang if your environment does not already provide a suitable C++20 compiler:

```bash
sudo apt-get install -y clang
```

## Build

```bash
git clone https://github.com/mushorg/glutton.git
cd glutton
export PATH=/opt/spicy/bin:$PATH
make spicy
make build
```

`make spicy` runs the Spicy Makefile in `protocols/spicy/`. It generates parser C++ files, parser headers, and a combined linker file. Those generated files are ignored by Git.

`make build` compiles `app/server.go` into `bin/server` and embeds version metadata from the top-level `Makefile`.

## Test

```bash
export PATH=/opt/spicy/bin:$PATH
make spicy
go test -v ./...
```

The GitHub Actions workflow runs `make spicy`, `go build -v ./...`, and `go test -v ./...` with `CC=clang` and `CXX=clang++`.

## Version Check

```bash
bin/server --version
```

The binary prints the Glutton banner and version string, then exits before initializing the honeypot runtime.

## CLI Flags

Flags are defined in `app/server.go`.

| Flag | Short | Type | CLI default | Purpose |
| --- | --- | --- | --- | --- |
| `--interface` | `-i` | string | `eth0` | Network interface used for public address discovery and TPROXY rules. |
| `--ssh` | `-s` | int | `22` | Overrides `ports.ssh` when supplied. See the configuration note about SSH defaults. |
| `--logpath` | `-l` | string | `/dev/null` | File path for rotating JSON logs. Logs also go to stdout. |
| `--confpath` | `-c` | string | `config/` | Directory where Viper looks for `config.yaml`. |
| `--debug` | `-d` | bool | `false` | Parsed and bound, but the current logger setup does not use it to lower the slog level. |
| `--version` | none | bool | `false` | Prints the banner/version and exits. |
| `--var-dir` | none | string | `/var/lib/glutton` | Directory where `glutton.id` is stored. |

## Run Locally

Glutton modifies iptables rules and normally needs root or equivalent privileges:

```bash
sudo bin/server --interface eth0 --confpath config/ --logpath glutton.log
```

The process starts local listeners on the configured TCP and UDP redirect ports, installs TPROXY rules, and then handles redirected traffic.

## Docker

The repository includes a multi-stage Dockerfile:

```bash
docker build -t glutton .
docker run --rm --cap-add=NET_ADMIN -it glutton
```

The container command runs:

```bash
./bin/server -i eth0 -l /var/log/glutton.log -d true
```

`--cap-add=NET_ADMIN` is required because Glutton manages iptables rules. The Dockerfile should be kept aligned with the Spicy requirements used in CI.
