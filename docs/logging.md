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
| `timestamp` | UTC time the event was produced. |
| `startedAt` | Connection (or datagram) start from the connection table (`md.Added`). |
| `durationMs` | Milliseconds from `startedAt` to produce time. |
| `transport` | `tcp` or `udp`. |
| `srcHost` | Source IP. |
| `srcPort` | Source port. |
| `srcPtr` | First reverse-DNS name when a PTR lookup already ran (not on CIDR-matched scanners). |
| `dstHost` | Original destination IP (TPROXY `LocalAddr` / UDP dest). |
| `dstPort` | Original destination port from metadata. |
| `sensorID` | Glutton sensor ID. |
| `sensorVersion` | Build version (`VERSION` / `sensor_version`). |
| `rule` | Rule match string when metadata includes a rule. |
| `ruleName` | Optional `name` from `rules.yaml`. |
| `handler` | Handler name supplied by the protocol handler. |
| `payload` | Base64-encoded first-frame payload bytes. |
| `payloadHash` | SHA-256 hex of the (sanitized) top-level payload. |
| `frameCount` | Number of decoded frames when `decoded` is a slice. |
| `endReason` | Why the session ended (`client_close`, `timeout`, `handler_close`, `read_error`, `write_error`, `max_frames`). Omitted by handlers that do not set it. |
| `scanner` | Scanner classification from `scanner.Classify(...)`. |
| `decoded` | Handler-specific decoded data. |

Events are emitted only when (1) `producers.enabled` is true so a producer object exists, (2) a handler calls `ProduceTCP(...)` or `ProduceUDP(...)`, (3) the matched rule does not set `produce: false`, and (4) at least one sink is enabled. Before output, configured `addresses` values are scrubbed from payload bytes (ASCII and UTF-16LE) and replaced with `1.2.3.4`. The same sanitizer runs on each decoded frame `payload` / `path`.

Array-of-frames `decoded` entries share these JSON names when the handler fills them: `direction`, `payload`, `command` (leaf operation), `path`, `status` (writes), `truncated`. Handler-specific fields sit beside them.

Example shape:

```json
{
  "timestamp": "2026-05-15T12:00:00Z",
  "transport": "tcp",
  "srcHost": "203.0.113.10",
  "srcPort": "54321",
  "dstHost": "192.0.2.10",
  "dstPort": 80,
  "sensorID": "00000000-0000-0000-0000-000000000000",
  "sensorVersion": "v0.0.0",
  "rule": "Rule: tcp",
  "frameCount": 1,
  "endReason": "client_close",
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
| `http` (Go) | Array of per-direction frames: `direction`, `command`, `path`, `query`, `host`, `user_agent`, `status`, `session_id`, `payload` | Keep-alive HTTP. `command` is the HTTP method. Writes set `status` (e.g. `200`). Responses set a `session` cookie; frames that share that cookie (per source host) are grouped into one produced event when the session idles out (`conn_timeout`). Shares the idle session table with `mcp`. |
| `http` (Spicy) | `{method, url, path, query}` | Request body is the event payload. |
| `tcp` | Array of per-direction frames: `direction`, `payload`, `payload_hash` | Catch-all. Client bytes are one `read` frame (capped by `max_tcp_payload`); the honeypot replies with random bytes as a `write` frame. |
| `udp` | Array of read frames: `direction`, `payload`, `payload_hash`, `truncated` | Catch-all. One datagram per event (capped at 1024 bytes). `truncated` is set when the datagram was longer. The handler does not reply. Datagrams with RakNet offline magic are rerouted to `raknet`; APPLICATION 10/12 Kerberos AS-REQ/TGS-REQ are rerouted to `kerberos`; CoAP version-1 GET/POST/PUT/DELETE datagrams are rerouted to `coap`. |
| `proxy_tcp`, `proxy_udp` | Per-direction entries: `direction`, `payload`, `payload_hash`, `bytes`, `truncated` | Only when `capture_traffic.enabled` is true. Samples are capped by `max_tcp_payload`; `truncated` is whether more bytes were forwarded than captured. `proxy_udp` emits one event per flow when the flow idles out or closes. |
| `sip` (TCP/UDP) | Array of per-direction frames: `direction`, `payload`, `message` | UDP OPTIONS probes get a `write` frame with the `200 OK` response. |
| `openvpn` (UDP) | Array of read frames: `direction`, `opcode`, `opcode_name`, `key_id`, `session_id` (hex), `payload` | The handler does not reply. |
| `mdns` (UDP) | Array of read frames: `direction`, `questions` (`qname`, `qtype`, `qtype_name`, `qclass`), `payload` | The handler does not reply. |
| `l2tp` (UDP) | Array of per-direction frames: `direction`, `message_type`, `message_name`, `host_name`, `vendor_name`, `tunnel_id`, `assigned_tunnel_id`, `ns`, `nr`, `payload` | SCCRQ probes get a `write` frame with an SCCRP reply. |
| `raknet` (UDP) | Array of read frames: `direction`, `packet_id`, `packet_name`, `protocol`, `magic_ok`, `mtu`, `payload` | Minecraft Bedrock / RakNet. Parse-only; no Open Connection Reply or Unconnected Pong. `0x05` OCR1 sets `protocol` (byte after magic) and `mtu` (datagram length). Generic UDP peeks the same magic and reroutes here. |
| `kerberos` (UDP) | Array of read frames: `direction`, `msg_type`, `msg_name`, `pvno`, `realm`, `sname`, `cname`, `etypes`, `from`, `nonce`, `payload` | Kerberos AS-REQ (`msg_type` 10) / TGS-REQ (12). Parse-only; no KRB-ERROR or AS-REP. Truncated or non-DER datagrams still emit a frame with raw `payload` (`msg_name` `UNKNOWN`). Generic UDP peeks APPLICATION 10/12 and reroutes here. |
| `coap` (UDP) | Array of per-direction frames: `direction`, `type`, `code`, `code_name`, `message_id`, `token` (hex), `path`, `observe`, `payload` | One datagram per event. CON/NON GET, POST, PUT, DELETE get a matching ACK/NON reply (`CONTENT` / `CREATED` / `DELETED`). GET `.well-known/core` returns CoRE Link Format `</ps/temp>,</ps/hum>`. Truncated or invalid datagrams still emit a `read` frame (`code_name` `UNKNOWN`). Generic UDP peeks version-1 request codes 1–4 and reroutes here. |
| `mqtt` (TCP) | Array of per-direction frames: `direction`, `packet`, `client_id`, `username`, `topic`, `topics`, `qos`, `payload` | One event per session. MQTT 3.1.1 remaining-length framing. CONNECT gets CONNACK accept; SUBSCRIBE gets SUBACK; QoS 1/2 PUBLISH get PUBACK/PUBREC; PINGREQ gets PINGRESP. `payload` is the raw packet including the header. Password bytes from CONNECT are not copied into `decoded`. |
| `memcache` (TCP) | Array of per-direction frames: `direction`, `command`, `payload` | `stats` probes get a `write` frame with a short fake `STAT`/`END` block. `set` frames aggregate the command line plus the data chunk. |
| `modbus` (TCP) | Array of per-direction frames: `direction`, `function_code`, `unit_id`, `address`, `quantity`, `payload` | One event per session. MBAP + PDU frames; `payload` is the full ADU. Writes echo the request transaction ID and unit ID. Function codes 1–6 / 15 / 16 are answered from per-session register maps (unread addresses read as zero). Unknown function codes get an illegal-function exception (`function_code` `Exception`). |
| `opcua` (TCP) | Array of per-direction frames: `direction`, `message_type`, `service`, `endpoint_url`, `security_policy`, `application_uri`, `application_name`, `username`, `payload` | One event per session. UACP frames (`HEL`/`ACK`/`ERR`/`OPN`/`MSG`/`CLO`/`RHE`); `payload` is the full message including the 8-byte header. Hello gets Acknowledge; Reverse Hello is logged and answered with Error (the handler never dials). None-security OpenSecureChannel, GetEndpoints, FindServers, CreateSession, ActivateSession, and Close* get stub success replies. Username identity is recorded; password bytes are not copied into `decoded`. |
| `mongodb` (TCP) | Array of per-direction frames: `direction`, `header`, `opcode_str`, `command`, `payload` | `command` is the BSON command name on read frames (`hello`, `isMaster`, `buildInfo`). OP_QUERY is answered with OP_REPLY and OP_MSG with OP_MSG; `hello`/`isMaster` get a fake handshake document (`ismaster`, `maxWireVersion`, …) and `buildInfo` a fake `version`/`versionArray`. |
| `mcp` (TCP) | Array of per-direction frames: `direction`, `command`, `path`, `session_id`, `payload` | Streamable HTTP JSON-RPC. `command` is the JSON-RPC method (e.g. `initialize`, `tools/list`) or the HTTP verb. `initialize` gets a JSON-RPC result plus `Mcp-Session-Id`; the connection stays open for further requests. Shares the idle session table with HTTP. |
| `telnet` (TCP) | Array of per-direction frames: `direction`, `message` | Telnet IAC negotiation is recorded as its own `read` frames so username/password/`message` values stay free of negotiation octets. |
| `smb` (TCP) | Array of per-direction frames: `direction`, `header`, `command`, `path`, `setup`, `status`, `nt_status`, `account`, `native_os`, `native_lanman`, `total_data_count`, `payload`, `truncated` | Direct TCP (port 445) length-prefixed SMB1 and SMB2. `command` is the opcode name. Tree Connect sets `path` to the share (`IPC$`); NT Create AndX sets `path` to the filename. Trans2 frames set `setup` (`TRANS2_SESSION_SETUP`, …). NT Transact reads set `total_data_count`. `SMB_COM_TRANSACTION2_SECONDARY` (`0x33`) and other secondary fragments are stored with no write; Echo copies request data. EternalBlue-class traffic can be `SMB_COM_NT_TRANSACT` (`0xa0`, often `total_data_count` `0x103d0`) plus many `0x33` sprays on one TCP session (not only `0xa1` / SMB2 grooms). Writes set `status` / `nt_status`. Session Setup copies Native OS/LanMan and account (no password). `header` JSON uses numeric tid/uid/mid/pid and hex `flags2`. |
| `rdp` (TCP) | Array of per-direction frames: `direction`, `command`, `cookie`, `protocols`, `header`, `payload` | `command` is `ConnectionRequest`, `ConnectionConfirm`, `TLSClientHello`, `TLSHandshake`, `MCSConnectInitial`, or `MCSConnectResponse`. `cookie` is `mstshash`; `protocols` is the RDP_NEG bitmask name. `header` is the TPKT (empty on TLS stub frames). |

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
