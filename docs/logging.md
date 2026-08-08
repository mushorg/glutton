# Logging and producers

Glutton has two output paths: process logs through Go `slog`, and optional producer events sent to HTTP or hpfeeds sinks. Handlers can emit both, but they're configured separately.

## Process logs

`producer.NewLogger(...)` creates a JSON `slog` logger that writes every record to:

- stdout
- the path configured by `--logpath`

The file writer uses lumberjack rotation: 200 MB max size, 356 days max age, compression on. Every record carries the `sensorID` attribute (read from / written to `<var-dir>/glutton.id`).

The `--debug` flag is parsed but not wired into `slog.HandlerOptions`, so it does not currently lower the log level.

## Producer events

Producer events follow the `producer.Event` schema:

| JSON field | Meaning |
| --- | --- |
| `timestamp` | UTC event timestamp. |
| `transport` | `tcp` or `udp`. |
| `srcHost` | Source IP. |
| `srcPort` | Source port. |
| `dstPort` | Original destination port from metadata. |
| `sensorID` | Glutton sensor ID. |
| `rule` | Rule string when metadata includes a rule. |
| `handler` | Handler name supplied by the protocol handler. |
| `payload` | Base64-encoded payload bytes. |
| `scanner` | Scanner classification from `scanner.IsScanner(...)`. |
| `decoded` | Handler-specific decoded data. |

Events are emitted only when (1) `producers.enabled` is true so a producer object exists, (2) a handler calls `ProduceTCP(...)` or `ProduceUDP(...)`, and (3) at least one sink is enabled. Before output, configured `addresses` values are scrubbed from the payload and replaced with `1.2.3.4`.

Example shape:

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

`decoded` is handler-specific. For `proxy_tcp`, it contains per-direction entries (`direction`, `payload`, `payload_hash`, `bytes`, `truncated`) when `capture_traffic.enabled` is true; samples are capped by `max_tcp_payload`, and `truncated` reflects whether more bytes were forwarded than captured.

## HTTP producer

When `producers.http.enabled` is true, Glutton marshals each event as JSON and POSTs it to `producers.http.remote` with `Content-Type: application/json`. From source:

- HTTP client timeout: 10s; TLS handshake timeout: 5s.
- Events from private source IPs are skipped.
- Userinfo in the remote URL is used as HTTP Basic Auth.
- Query strings in the configured URL are preserved.

## hpfeeds producer

When `producers.hpfeeds.enabled` is true, Glutton connects to the broker at startup and publishes gob-encoded `producer.Event` values to `producers.hpfeeds.channel`.

```yaml
producers:
  hpfeeds:
    enabled: false
    host: 172.26.0.2
    port: 20000
    ident: ident
    auth: auth
    channel: test
```

Treat all logged payloads as attacker-controlled data in downstream pipelines.
