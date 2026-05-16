# Frequently Asked Questions

Last verified against source on 2026-05-15.

## What is Glutton?

Glutton is a Go-based, multi-protocol honeypot. It redirects TCP and UDP traffic through local TPROXY listeners, applies rule-based dispatch, runs protocol handlers, and logs interaction data.

## Is Glutton high-interaction?

No. Glutton does not give attackers a real host or full service environment. It sits in the low-to-medium interaction range: handlers emulate enough protocol behavior to capture useful probes and payloads, but they are still controlled Go implementations.

## Which protocols are registered today?

TCP handler targets include SMTP, RDP, SMB, FTP, SIP, RFB/VNC, Telnet, MQTT, iSCSI, BitTorrent, Memcache, Jabber, ADB, MongoDB, HTTP, proxy TCP forwarding, and generic TCP. UDP currently has a generic UDP handler.

## Does Spicy parse every protocol?

No. Current Spicy grammar files are `http.spicy` and `tcp.spicy`. Spicy is used for selected HTTP parsing and TCP payload protocol detection paths. Most protocol behavior still lives in Go handlers.

## Why does a rule target of `http` use the Go HTTP handler?

`protocols/protocols.go` maps target `http` to `protocols/tcp/http.go`. The Spicy HTTP handler is reached from the generic `tcp` path when Spicy detection classifies a catch-all TCP payload as HTTP.

## What is the default SSH exclusion port?

The source has an ambiguity: `config/config.yaml` sets `ports.ssh: 2222`, while the CLI flag `--ssh` has default `22`. Set `ports.ssh` explicitly or pass `--ssh` explicitly in production.

## Are environment variables supported for config?

Not as a documented current behavior. The code binds CLI flags and reads YAML config through Viper, but does not call `viper.AutomaticEnv()`.

## Does `type: drop` drop traffic?

Not in the current listener dispatch path. The rules parser accepts `drop`, but Glutton does not currently special-case that rule type after a match. Treat it as unsupported for production drop behavior until code support is added and tested.

## What does `type: proxy_tcp` do?

`proxy_tcp` forwards a matched TCP connection to the rule target, which must be an upstream `host:port` address. It logs transfer metadata and can include bounded per-direction payload samples in decoded producer events when `capture_traffic.enabled` is true.

## Where do logs go?

Process logs are JSON `slog` records written to stdout and to `--logpath`. Producer events are separate and only go to HTTP or hpfeeds when producers and those sinks are enabled.

## What should I read before adding a protocol?

Read [Extension system](extension-system.md), then [Adding a protocol](protocols/adding-a-protocol.md). If you need Spicy parsing, read [Spicy cheatsheet](protocols/spicy-cheatsheet.md).
