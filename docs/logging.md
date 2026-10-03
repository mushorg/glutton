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

`decoded` is handler-specific:

| Handler | `decoded` | Notes |
| --- | --- | --- |
| `http` (Go) | Array of per-direction frames: `direction`, `command`, `path`, `query`, `session_id`, `payload` | Keep-alive HTTP. `command` is the HTTP method. Responses set a `session` cookie; frames that share that cookie (per source host) are grouped into one produced event when the session idles out (`conn_timeout`). Shares the idle session table with `mcp`. |
| `http` (Spicy) | `{method, url, path, query}` | Request body is the event payload. |
| `tcp` | Array of per-direction frames: `direction`, `payload`, `payload_hash` | Catch-all. Client bytes are one `read` frame (capped by `max_tcp_payload`); the honeypot replies with random bytes as a `write` frame. |
| `udp` | Array of read frames: `direction`, `payload` | Catch-all. One datagram per event (capped at 1024 bytes). The handler does not reply. Datagrams with RakNet offline magic are rerouted to `raknet`; APPLICATION 10/12 Kerberos AS-REQ/TGS-REQ are rerouted to `kerberos`. |
| `proxy_tcp`, `proxy_udp` | Per-direction entries: `direction`, `payload`, `payload_hash`, `bytes`, `truncated` | Only when `capture_traffic.enabled` is true. Samples are capped by `max_tcp_payload`; `truncated` is whether more bytes were forwarded than captured. `proxy_udp` emits one event per flow when the flow idles out or closes. |
| `sip` (TCP/UDP) | Array of per-direction frames: `direction`, `payload`, `message` | UDP OPTIONS probes get a `write` frame with the `200 OK` response. |
| `openvpn` (UDP) | Array of read frames: `direction`, `opcode`, `opcode_name`, `key_id`, `session_id` (hex), `payload` | The handler does not reply. |
| `mdns` (UDP) | Array of read frames: `direction`, `questions` (`qname`, `qtype`, `qtype_name`, `qclass`), `payload` | The handler does not reply. |
| `l2tp` (UDP) | Array of per-direction frames: `direction`, `message_type`, `message_name`, `host_name`, `vendor_name`, `tunnel_id`, `assigned_tunnel_id`, `ns`, `nr`, `payload` | SCCRQ probes get a `write` frame with an SCCRP reply. |
| `raknet` (UDP) | Array of read frames: `direction`, `packet_id`, `packet_name`, `protocol`, `magic_ok`, `mtu`, `payload` | Minecraft Bedrock / RakNet. Parse-only; no Open Connection Reply or Unconnected Pong. `0x05` OCR1 sets `protocol` (byte after magic) and `mtu` (datagram length). Generic UDP peeks the same magic and reroutes here. |
| `kerberos` (UDP) | Array of read frames: `direction`, `msg_type`, `msg_name`, `pvno`, `realm`, `sname`, `cname`, `etypes`, `from`, `nonce`, `payload` | Kerberos AS-REQ (`msg_type` 10) / TGS-REQ (12). Parse-only; no KRB-ERROR or AS-REP. Truncated or non-DER datagrams still emit a frame with raw `payload` (`msg_name` `UNKNOWN`). Generic UDP peeks APPLICATION 10/12 and reroutes here. |
| `memcache` (TCP) | Array of per-direction frames: `direction`, `command`, `payload` | `stats` probes get a `write` frame with a short fake `STAT`/`END` block. `set` frames aggregate the command line plus the data chunk. |
| `mongodb` (TCP) | Array of per-direction frames: `direction`, `header`, `opcode_str`, `command`, `payload` | `command` is the BSON command name on read frames (`hello`, `isMaster`, `buildInfo`). OP_QUERY is answered with OP_REPLY and OP_MSG with OP_MSG; `hello`/`isMaster` get a fake handshake document (`ismaster`, `maxWireVersion`, …) and `buildInfo` a fake `version`/`versionArray`. |
| `mcp` (TCP) | Array of per-direction frames: `direction`, `command`, `path`, `session_id`, `payload` | Streamable HTTP JSON-RPC. `command` is the JSON-RPC method (e.g. `initialize`, `tools/list`) or the HTTP verb. `initialize` gets a JSON-RPC result plus `Mcp-Session-Id`; the connection stays open for further requests. Shares the idle session table with HTTP. |
| `telnet` (TCP) | Array of per-direction frames: `direction`, `message` | Telnet IAC negotiation is recorded as its own `read` frames so username/password/`message` values stay free of negotiation octets. |
| `smb` (TCP) | Array of per-direction frames: `direction`, `header`, `command`, `path`, `payload`, `truncated` | Direct TCP (port 445) length-prefixed SMB1 and SMB2. `command` is the opcode name (`SMB_COM_NT_CREATE_ANDX`, `SMB_COM_NT_TRANSACT`, `SMB2_NEGOTIATE`, …). SMB1 NT Create AndX read frames set `path` to the requested filename (e.g. `\svcctl`). `payload` includes the 4-byte session header; `truncated` is set when the PDU exceeded the 256 KiB capture cap. SMB1 `0x25` still returns `STATUS_INSUFF_SERVER_RESOURCES`; `0xA0` NT Transact gets a success stub so large follow-on bodies are stored; `0xA2` NT Create AndX gets WordCount 34 with a FID. See the skill reference. |
| `rdp` (TCP) | Array of per-direction frames: `direction`, `header`, `payload` | `header` is the TPKT (empty on TLS stub frames). Connection Confirm is 11 bytes with no `RDP_NEG_RSP` when the client Connection Request omitted `RDP_NEG_REQ`, and 19 bytes selecting TLS\|CredSSP when negotiation was requested. MCS Connect-Initial (X.224 DT) is a separate read frame and is answered with MCS Connect-Response, not a second X.224 CC. |

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
