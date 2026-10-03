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

Events are emitted only when (1) `producers.enabled` is true so a producer object exists, (2) a handler calls `ProduceTCP(...)` or `ProduceUDP(...)`, (3) the matched rule does not set `produce: false`, and (4) at least one sink is enabled. Before output, configured `addresses` values are scrubbed from the payload and replaced with `1.2.3.4`.

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
  "decoded": [
    {
      "direction": "read",
      "command": "GET",
      "path": "/",
      "session_id": "11111111-1111-1111-1111-111111111111",
      "payload": "R0VUIC8gSFRUUC8xLjENCg0K"
    }
  ]
}
```

`decoded` is handler-specific. For TCP `http` (Go handler), it is an array of per-direction frames (`direction`, `command`, `path`, `query`, `session_id`, `payload`) for a keep-alive HTTP session; `command` is the HTTP method; responses set a `session` cookie, and frames that share that cookie (per source host) are grouped into one produced event when the session idles out (`conn_timeout`). The Spicy HTTP handler still emits `{method, url, path, query}` with the request body as the event payload. For `proxy_tcp` and `proxy_udp`, it contains per-direction entries (`direction`, `payload`, `payload_hash`, `bytes`, `truncated`) when `capture_traffic.enabled` is true; samples are capped by `max_tcp_payload`, and `truncated` reflects whether more bytes were forwarded than captured. `proxy_udp` emits one event per flow when the flow idles out or closes. For TCP/UDP `sip`, it is an array of per-direction frames (`direction`, `payload`, `message`); UDP OPTIONS probes get a `write` frame with the `200 OK` response. For UDP `openvpn`, it is an array of read frames (`direction`, `opcode`, `opcode_name`, `key_id`, `session_id` as hex, `payload`); the handler does not reply. For UDP `mdns`, it is an array of read frames (`direction`, `questions` with `qname`/`qtype`/`qtype_name`/`qclass`, `payload`); the handler does not reply. For UDP `l2tp`, it is an array of per-direction frames (`direction`, `message_type`, `message_name`, `host_name`, `vendor_name`, `tunnel_id`, `assigned_tunnel_id`, `ns`, `nr`, `payload`); SCCRQ probes get a `write` frame with an SCCRP reply. For TCP `memcache`, it is an array of per-direction frames (`direction`, `command`, `payload`); `stats` probes get a `write` frame with a short fake `STAT`/`END` block, and `set` frames aggregate the command line plus the data chunk. For TCP `mongodb`, it is an array of per-direction frames (`direction`, `header`, `opcode_str`, `command`, `payload`); `command` is the BSON command name on read frames (`hello`, `isMaster`, `buildInfo`). OP_QUERY is answered with OP_REPLY and OP_MSG with OP_MSG; `hello`/`isMaster` get a fake handshake document (`ismaster`, `maxWireVersion`, …) and `buildInfo` a fake `version`/`versionArray`. For TCP `mcp`, it is an array of per-direction frames (`direction`, `command`, `path`, `session_id`, `payload`) for an MCP-over-HTTP session; `command` is the JSON-RPC method (e.g. `initialize`, `tools/list`) or the HTTP verb; `initialize` gets a JSON-RPC result plus `Mcp-Session-Id`, and the connection stays open for further requests. HTTP and MCP share the same idle session table implementation. For TCP `telnet`, it is an array of per-direction frames (`direction`, `message`); telnet IAC negotiation is recorded as its own `read` frames so username/password/`message` values stay free of negotiation octets. For TCP `smb`, it is an array of per-direction frames (`direction`, `header`, `payload`) for an SMB1 session; see the skill reference for command-specific reply notes.

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
