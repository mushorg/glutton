# Glutton

[![Tests](https://github.com/mushorg/glutton/actions/workflows/workflow.yml/badge.svg)](https://github.com/mushorg/glutton/actions/workflows/workflow.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mushorg/glutton.svg)](https://pkg.go.dev/github.com/mushorg/glutton)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mushorg/glutton)](go.mod)
[![License](https://img.shields.io/github/license/mushorg/glutton)](LICENSE)

Glutton is a highly sensitive, protocol-agnostic, low-to-medium interaction honeypot built in Go. It uses iptables and TPROXY to redirect TCP and UDP traffic through local handlers, then logs interactions and payloads to help analyze malicious activity.

Glutton catches activity that traditional honeypots can miss: low-volume scans on non-standard ports, traffic that never completes a valid protocol handshake, and incomplete or incorrect protocol usage. With catch-all TCP and UDP rules, it can accept traffic across exposed ports even when no protocol-specific handler exists, then use the dynamic rules engine to route known traffic to built-in protocol handlers or fall back to generic capture.

Security teams can run Glutton as a standalone honeypot sensor or as a front door for a broader deception network. Glutton's open architecture makes it straightforward to add new protocol handlers and parser-backed paths.

Note: Zeek/Spicy-based protocol and file parsing should be treated as beta/staging-oriented. This branch includes selected Spicy parser paths for HTTP parsing and TCP payload protocol detection; it does not include a full Zeek correlation layer.



## Quick Start

Glutton uses iptables TPROXY and must run on Linux with privileges to manage network rules. The current CI build installs Spicy 1.13.1, clang, libpcap, iptables, zlib, and Go 1.23.

```bash
git clone https://github.com/mushorg/glutton.git
cd glutton

# Install Spicy/HILTI under /opt/spicy first, then:
export PATH=/opt/spicy/bin:$PATH
make spicy
make build

sudo bin/server --interface eth0 --confpath config/ --logpath glutton.log
```

Docker support is available through the repository Dockerfile:

```bash
docker build -t glutton .
docker run --rm --cap-add=NET_ADMIN -it glutton
```

If a Docker or local build fails in the Spicy-linked path, use the GitHub Actions workflow as the dependency source of truth and make sure Spicy/HILTI headers and libraries are available under `/opt/spicy`.

## What Glutton Captures

- TCP and UDP traffic redirected to local listener ports with iptables TPROXY.
- Rule matches from `config/rules.yaml`, using BPF-style match expressions.
- Protocol handler output for SMTP, RDP, SMB, FTP, SIP, RFB/VNC, Telnet, MQTT, iSCSI, BitTorrent, Memcache, Jabber, ADB, MongoDB, HTTP, generic TCP, and generic UDP.
- JSON process logs through `slog`.
- Optional producer events sent to HTTP endpoints or hpfeeds when producers are enabled.
- Spicy-backed HTTP parsing and TCP payload protocol detection where the current implementation wires those paths.

## Where It Fits

Glutton is not a SIEM, not a full high-interaction honeynet, and not a Cowrie replacement for SSH-only deployments. It is a multi-protocol sensor: useful when you want broad TCP/UDP exposure, configurable routing, structured payload capture, and a Go codebase that can grow new handlers and Spicy parsers.

## Documentation

- [Introduction](docs/index.md)
- [Setup](docs/setup.md)
- [Deployment](docs/deployment.md)
- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Rules engine](docs/rules-engine.md)
- [Logging and producers](docs/logging.md)
- [Extension system](docs/extension-system.md)
- [Adding a protocol](docs/protocols/adding-a-protocol.md)
- [Spicy cheatsheet](docs/protocols/spicy-cheatsheet.md)
- [Troubleshooting](docs/troubleshooting.md)
- [FAQ](docs/faq.md)
- [Contributing](CONTRIBUTING.md)

## License

Glutton is licensed under the [MIT License](LICENSE).
