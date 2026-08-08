# Glutton

[![Tests](https://github.com/mushorg/glutton/actions/workflows/workflow.yml/badge.svg)](https://github.com/mushorg/glutton/actions/workflows/workflow.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mushorg/glutton.svg)](https://pkg.go.dev/github.com/mushorg/glutton)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mushorg/glutton)](go.mod)
[![License](https://img.shields.io/github/license/mushorg/glutton)](LICENSE)
[![Discord](https://img.shields.io/badge/discord-Honeynet-5865F2?logo=discord&logoColor=white)](https://discord.gg/xzESEhgPtk)

> A highly sensitive, protocol-agnostic, low-interaction TCP/UDP honeypot in Go.

Modern attackers increasingly rely on stealthy techniques like low-volume scans, partial protocol handshakes, and subtle behavioral anomalies to evade detection by conventional honeypots. These systems often fail to capture such activities due to rigid protocol emulation, incomplete logging, or reliance on predefined attack signatures.

Glutton is built to bridge this gap with its catch-all TCP/UDP approach. It captures traffic across all TCP and UDP ports and protocols without requiring a specific protocol implementation for each service. Its dynamic rule engine then either redirects traffic to a protocol-specific handler, forwards it to an upstream target through the built-in TCP proxy, or captures it generically so the payload is preserved even when the protocol is unknown. Together, this gives security teams visibility into reconnaissance activities that might otherwise go undetected.

Glutton's core is designed for:

- **Protocol-agnosticism:** Instead of fully emulating each protocol, Glutton uses configurable rules and generic handlers to process any TCP/UDP-based interaction on all ports.
- **Detailed logging:** Glutton records all connections, including metadata and payloads, to preserve even partial interactions for further analysis.
- **Extensibility:** Its flexible mapping of protocol handlers and configurable rules allows it to quickly adapt to support new protocols without the need for extensive architectural changes.

Beyond Go handlers, Glutton also includes an emerging Spicy parser path. Spicy is the parser-definition language from the Zeek project; it lets contributors describe byte-level protocol grammars in a small DSL instead of writing the parser in Go. Currently Glutton uses Spicy for HTTP parsing and TCP-payload protocol detection only.

Out of the box, Glutton ships handlers that capture exploit probes targeting Citrix ADC (CVE-2019-19781), VMware vCenter (`hyper/send`), and Ethereum JSON-RPC wallets, alongside protocol-interaction handlers for SMTP, RDP, SMB, and many more, plus generic TCP/UDP fallbacks and TCP proxy forwarding for everything else. See [What Glutton captures](#what-glutton-captures) below for the full list.

## Quick start

Glutton requires Linux, root privileges for iptables, and a build toolchain compatible with the [CI workflow](.github/workflows/workflow.yml) — currently Go 1.23+, Spicy 1.13.1, clang 17, libpcap, iptables, and zlib1g.

```bash
git clone https://github.com/mushorg/glutton.git
cd glutton

# Install Spicy/HILTI under /opt/spicy (see docs/setup.md), then:
export PATH=/opt/spicy/bin:$PATH
make spicy
make build

sudo bin/server -i eth0 -c config/ -l /var/log/glutton.log
```

> **SSH safety:** Glutton's iptables rule excludes one TCP port from TPROXY redirection so your SSH session survives. Both `ports.ssh` (`config/config.yaml`) and the CLI flag `-s/--ssh` (`app/server.go`) default to `2222`. If your sshd listens on a different port (the typical `22`, for example), set `ports.ssh` in your config or pass `-s <port>` explicitly to the port your sshd actually listens on before exposing the sensor, or you will lock yourself out.

Edit `config/config.yaml` before deployment. Set `addresses` to your host's public IPs and review `ports.`*, `producers.`*, `capture_traffic.enabled`, `dial_timeout`, and the rules in `config/rules.yaml`. Full reference in [docs/configuration.md](docs/configuration.md).

For full build, install, and runtime details — including Spicy setup, privileges, and operational hazards — see [docs/setup.md](docs/setup.md).

## Docker

The repository ships a `Dockerfile`. For real traffic capture the container needs the host network namespace and `NET_ADMIN`, since TPROXY operates on a real interface:

```bash
docker build -t glutton .
docker run --rm --network host --cap-add=NET_ADMIN -it glutton
```

This requires the host kernel to support iptables `mangle` and the `xt_TPROXY` module. Without `--network host` the container will install rules inside the container network namespace and never see external traffic.

For full Docker, privileges, and host-placement guidance, see [docs/setup.md](docs/setup.md).

## What Glutton captures


| Name                        | What it captures                         |
| --------------------------- | ---------------------------------------- |
| Citrix ADC (CVE-2019-19781) | `GET /vpn/*` RCE probes                  |
| VMware "hyper/send"         | `* hyper/send` request-body exploit      |
| Ethereum JSON-RPC           | `POST` body containing `eth_blockNumber` |
| Wallet probes               | URIs containing `wallet`                 |
| SMTP                        | mail submission probes                   |
| RDP                         | Remote Desktop handshake                 |
| SMB                         | Windows file-sharing probes              |
| FTP                         | file transfer commands                   |
| SIP                         | VoIP signaling traffic                   |
| RFB/VNC                     | remote framebuffer auth                  |
| Telnet                      | interactive login attempts               |
| MQTT                        | IoT pub/sub messages                     |
| iSCSI                       | block-storage target probes              |
| BitTorrent                  | peer handshake traffic                   |
| Memcache                    | key-value cache commands                 |
| Jabber/XMPP                 | instant messaging stream                 |
| ADB                         | Android Debug Bridge probes              |
| MongoDB                     | wire protocol queries                    |
| Hadoop YARN                 | `POST */cluster/apps/new-application`    |
| Docker Engine API           | `GET /v1.16/version`                     |
| HTTP                        | generic web requests                     |
| generic TCP                 | unrecognized TCP payloads                |
| generic UDP                 | unrecognized UDP payloads                |


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

## Where it fits

Glutton is a breadth-oriented sensor: it trades the deep per-protocol emulation of specialized honeypots for coverage across the TCP/UDP port space. It is not a SIEM, not a high-interaction honeynet, and not a Cowrie replacement for SSH-only deployments. Compared to tools such as Cowrie (SSH/Telnet, high-interaction shell), Dionaea (malware capture), and T-Pot (bundled distribution), Glutton's distinctive surface is broad protocol coverage in one Go binary, a dynamic rule engine, `proxy_tcp` forwarding, and a parser-extension path that can grow with new protocols.

## Documentation

- [Getting started](docs/setup.md)
- [Configuration](docs/configuration.md)
- [Architecture](docs/architecture.md)
- [Logging and producers](docs/logging.md)
- [Extension system](docs/extension-system.md) · [Adding a protocol](docs/protocols/adding-a-protocol.md) · [Spicy cheatsheet](docs/protocols/spicy-cheatsheet.md)
- [FAQ](docs/faq.md)

## Community and contributing

Glutton was built by [Lukas Rist](https://github.com/glaslos), [Muhammad Bilal Arif](https://github.com/furusiyya), and [the community](https://github.com/mushorg/glutton/graphs/contributors?all=1).

For contributing see:

- Contributor guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Issues and PRs: [github.com/mushorg/glutton](https://github.com/mushorg/glutton)
- Chat: [Honeynet Project Discord](https://discord.gg/xzESEhgPtk)

## License

Glutton is released under the [MIT License](LICENSE).