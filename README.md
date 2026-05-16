# Glutton

[![Tests](https://github.com/mushorg/glutton/actions/workflows/workflow.yml/badge.svg)](https://github.com/mushorg/glutton/actions/workflows/workflow.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mushorg/glutton.svg)](https://pkg.go.dev/github.com/mushorg/glutton)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mushorg/glutton)](go.mod)
[![License](https://img.shields.io/github/license/mushorg/glutton)](LICENSE)
[![Discord](https://img.shields.io/discord/415692350448746497?label=discord)](https://discord.gg/rUgDRn3R)

> A highly sensitive, protocol-agnostic TCP/UDP honeypot in Go.

Glutton is built to catch activity that traditional single-service honeypots can miss: low-volume scans on non-standard ports, partial protocol handshakes, and incomplete or incorrect protocol usage. It uses iptables and TPROXY to redirect TCP and UDP traffic through local listeners, applies a dynamic rule engine, and records interaction metadata and payloads for analysis.

Glutton can accept traffic across exposed TCP and UDP ports even when no protocol-specific handler exists. Known traffic can be routed to built-in protocol handlers, proxied to an upstream TCP service with `proxy_tcp`, or captured through generic fallback handlers.

Security teams can run Glutton as a standalone honeypot sensor or as a front door for a broader deception network. Its open handler and parser architecture makes it straightforward to add new protocol handling paths as attacker behavior changes.

Note: Zeek/Spicy-based protocol and file parsing should be treated as beta/staging-oriented. This branch includes selected Spicy parser paths for HTTP parsing and TCP payload protocol detection; it does not include a full Zeek correlation layer.

## Quick Start

Glutton requires Linux, root privileges for iptables, and a build toolchain compatible with the [CI workflow](.github/workflows/workflow.yml): Go 1.23+, Spicy 1.13.1, clang, libpcap, iptables, and zlib.

```bash
git clone https://github.com/mushorg/glutton.git
cd glutton

# Install Spicy/HILTI under /opt/spicy first.
export PATH=/opt/spicy/bin:$PATH
make spicy
make build

sudo bin/server -i eth0 -c config/ -l glutton.log
```

SSH safety: Glutton's iptables rule excludes one TCP port from TPROXY redirection so your SSH session survives. The config default and CLI default differ today, so set `ports.ssh` in config or pass `-s <port>` explicitly before exposing a sensor.

Edit `config/config.yaml` before deployment. Set `addresses` to your host's public IPs and review `ports.*`, `producers.*`, `capture_traffic.enabled`, `dial_timeout`, and the rules in `config/rules.yaml`.

## Docker

The repository ships a Dockerfile:

```bash
docker build -t glutton .
docker run --rm --network host --cap-add=NET_ADMIN -it glutton
```

For real traffic capture, the container needs the host network namespace and `NET_ADMIN` because TPROXY operates on a real interface. Without `--network host`, the container will install rules inside the container network namespace and may never see external traffic.

## What Glutton Captures

- TCP and UDP traffic redirected to local listener ports with iptables TPROXY.
- Rule matches from `config/rules.yaml`, using BPF-style match expressions.
- Protocol handler output for SMTP, RDP, SMB, FTP, SIP, RFB/VNC, Telnet, MQTT, iSCSI, BitTorrent, Memcache, Jabber, ADB, MongoDB, HTTP, generic TCP, and generic UDP.
- TCP proxy forwarding for rules with `type: proxy_tcp`, including optional bounded per-direction payload capture.
- JSON process logs through `slog`.
- Optional producer events sent to HTTP endpoints or hpfeeds when producers are enabled.
- Spicy-backed HTTP parsing and TCP payload protocol detection where the current implementation wires those paths.

Example producer event shape:

```json
{
  "timestamp": "2026-05-15T12:00:00Z",
  "transport": "tcp",
  "srcHost": "203.0.113.10",
  "srcPort": "54321",
  "dstPort": 80,
  "sensorID": "00000000-0000-0000-0000-000000000000",
  "rule": "Rule: tcp",
  "handler": "http",
  "payload": "R0VUIC8gSFRUUC8xLjENCg0K",
  "scanner": "",
  "decoded": { "protocol": "http", "fields": {} }
}
```

## Where It Fits

Glutton is a breadth-oriented sensor: it trades the deep per-protocol emulation of specialized honeypots for coverage across the TCP/UDP port space. It is not a SIEM, not a high-interaction honeynet, and not a Cowrie replacement for SSH-only deployments.

Compared to tools such as Cowrie, Dionaea, and T-Pot, Glutton's distinctive surface is broad protocol coverage in one Go binary, a dynamic rule engine, proxy TCP forwarding, and a parser-extension path that can grow with new protocols.

## Documentation

**Get started**

- [Introduction](docs/index.md)
- [Setup](docs/setup.md)
- [Deployment](docs/deployment.md)

**Operate**

- [Configuration](docs/configuration.md)
- [Rules engine](docs/rules-engine.md)
- [Logging and producers](docs/logging.md)
- [Troubleshooting](docs/troubleshooting.md)

**Understand**

- [Architecture](docs/architecture.md)
- [FAQ](docs/faq.md)

**Extend**

- [Extension system](docs/extension-system.md)
- [Adding a protocol](docs/protocols/adding-a-protocol.md)
- [Spicy cheatsheet](docs/protocols/spicy-cheatsheet.md)

## Community And Contributing

- Chat: [Honeynet Project Discord](https://discord.gg/rUgDRn3R)
- Issues and PRs: [github.com/mushorg/glutton](https://github.com/mushorg/glutton)
- Contributor guide: [CONTRIBUTING.md](CONTRIBUTING.md)

## Citation

If you use Glutton in academic or industry work, please cite:

> Arif, M. B., Rist, L., & Ghazi, Y. (2025). *Glutton: A Highly Sensitive, Protocol-Agnostic Honeypot.* The Honeynet Project.

## License

Glutton is released under the [MIT License](LICENSE).
