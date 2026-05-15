# Introduction

Glutton is a highly sensitive, protocol-agnostic, low-to-medium interaction honeypot for observing internet-facing service probes and payloads without running the real services being targeted. It is built in Go and uses iptables plus TPROXY to redirect TCP and UDP traffic through local listeners, apply rule-based dispatch, hand connections to protocol handlers, and record interaction data through JSON logs and optional producers.

Glutton is designed to catch activity that traditional single-service honeypots can miss, including low-volume scans on non-standard ports, traffic that never completes a valid handshake, and incomplete or incorrect protocol usage. With catch-all TCP and UDP rules, it can accept traffic across exposed ports even when no protocol-specific handler exists, then route known traffic to protocol handlers or fall back to generic capture.

Glutton can run as a standalone honeypot sensor or as a front door for a broader deception network. Existing Go handlers and selected Spicy parsers can interpret traffic and payloads across supported paths, while new handlers and parsers can be added for emerging protocols.

Glutton sits in the low-to-medium interaction part of the honeypot landscape. It is not a full host or shell for attackers, but it does more than count connection attempts: several handlers speak enough of their protocol to capture useful payloads, return believable responses, and preserve decoded details for downstream analysis.

Note: Zeek/Spicy work should be treated as beta/staging-oriented. This branch includes selected Spicy parser paths for HTTP parsing and TCP payload protocol detection; it does not include a full Zeek correlation layer.

## Where Glutton Fits

Use Glutton when you want:

- one Go binary that can expose many TCP and UDP service surfaces
- BPF-style rules that route traffic to named handlers
- structured logs and producer events for later analysis
- a codebase where new handlers can be added without operating a full honeynet
- selected Spicy parser support for structured payload parsing

Glutton is different from SSH-focused honeypots such as Cowrie, malware-collection tools such as Dionaea, and bundled distributions such as T-Pot. Those tools remain useful in their niches. Glutton's strength is broad protocol coverage in one Go sensor, plus an extension path where byte-level parsers and Go handlers can evolve independently.

## What Glutton Is Not

Glutton is not:

- a SIEM or long-term analysis platform
- a high-interaction virtual machine honeynet
- a complete replacement for specialized honeypots such as Cowrie
- a firewall, even though it manages iptables rules for transparent proxying
- a project where Spicy currently parses every protocol path

## How To Read These Docs

- Start with [Setup](setup.md) if you want to build or test Glutton locally.
- Read [Deployment](deployment.md) before exposing a sensor to hostile traffic.
- Read [Architecture](architecture.md) to understand how redirected traffic becomes handler output.
- Read [Configuration](configuration.md) and [Rules engine](rules-engine.md) before changing ports, rules, or producers.
- Read [Extension system](extension-system.md) and [Adding a protocol](protocols/adding-a-protocol.md) before adding a new protocol handler or Spicy parser.

## Source Verification

These docs were rewritten against the implementation on 2026-05-15. Defaults, flags, build requirements, handler names, logging fields, and parser coverage are intentionally tied to source files such as `app/server.go`, `config/config.yaml`, `protocols/protocols.go`, `producer/producer.go`, and `protocols/spicy/`.
