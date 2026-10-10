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

| JSON field | Type | Meaning |
| --- | --- | --- |
| `timestamp` | string (RFC 3339) | UTC time the event was produced. |
| `startedAt` | string (RFC 3339) | Connection (or datagram) start from the connection table (`md.Added`). Go does not omit a zero `time.Time`, so an unknown start is `0001-01-01T00:00:00Z`, not absent. |
| `durationMs` | number, optional | Milliseconds from `startedAt` to produce time. Omitted when 0. |
| `transport` | string | `tcp` or `udp`. |
| `srcHost` | string | Source IP. |
| `srcPort` | **string** | Source port. Unlike `dstPort`, this is a string. |
| `srcPtr` | string, optional | First reverse-DNS name when a PTR lookup already ran (not on CIDR-matched scanners). |
| `dstHost` | string, optional | Original destination IP (TPROXY `LocalAddr` / UDP dest). This is the sensor's address; strip it before showing events publicly. |
| `dstPort` | number | Original destination port from metadata. |
| `sensorID` | string | Glutton sensor ID. |
| `sensorVersion` | string, optional | Build version (`VERSION` / `sensor_version`). |
| `rule` | string, optional | Rule match string when metadata includes a rule. |
| `ruleName` | string, optional | Optional `name` from `rules.yaml`. |
| `handler` | string | Handler name supplied by the protocol handler. |
| `payload` | string (base64), optional | First-frame payload bytes. |
| `payloadHash` | string (hex), optional | SHA-256 of the (sanitized) top-level payload. |
| `frameCount` | number, optional | Number of decoded frames when `decoded` is a slice. Omitted when 0. |
| `endReason` | string, optional | Why the session ended (`client_close`, `timeout`, `handler_close`, `read_error`, `write_error`, `max_frames`, `evicted`). `evicted` means the handler's session table was full and the least recently active session was flushed early. Omitted by handlers that do not set it. |
| `tls` | object, optional | Present only when the sensor terminated TLS. See [TLS details](#tls-details). |
| `scanner` | string, optional | Scanner classification from `scanner.Classify(...)`. Omitted when empty. |
| `decoded` | array, object or `null`, optional | Handler-specific decoded data. See [Decoded data](#decoded-data). |

All optional fields use `omitempty`: an empty string, a zero number or a nil value is left out of the JSON instead of being sent as `""`, `0` or `null`.

Events are emitted only when (1) `producers.enabled` is true so a producer object exists, (2) a handler calls `ProduceTCP(...)` or `ProduceUDP(...)`, (3) the matched rule does not set `produce: false`, and (4) at least one sink is enabled. Before output, configured `addresses` values are scrubbed from payload bytes (ASCII and UTF-16LE) and replaced with `1.2.3.4`. The same sanitizer runs on every string and byte slice inside `decoded` (frame fields such as `from`, `to`, `endpoint_url`, nested structs, maps), so the sensor address never appears in decoded output; fixed-size byte arrays are left alone. Events from sensors built before commit 937dcd8 (after v1.0.1) only scrubbed `payload` and `path`.

### TLS details

`tls` is set when the rule has `tls: true`, or `tls: auto` and the client opened with a ClientHello. `decoded` and `payload` then hold the decrypted plaintext protocol, so a display should say that the session was TLS.

| Field | Type | Meaning |
| --- | --- | --- |
| `serverName` | string, optional | SNI from the ClientHello. |
| `alpn` | array of strings, optional | Protocols offered by the client. |
| `version` | string, optional | Negotiated TLS version, e.g. `TLS 1.3`. |
| `cipher` | string, optional | Negotiated cipher suite. Empty (so omitted) when the handshake failed. |
| `clientHello` | string (base64), optional | Raw ClientHello records, capped at 4 KiB. |
| `truncated` | boolean, optional | Set when `clientHello` was cut at the cap. |

## Decoded data

Value encodings inside `decoded` follow Go's `encoding/json`:

- Byte slices (`[]byte`) are base64 strings. Frame `payload` fields are always base64.
- Fields documented as "(hex)" are hex strings produced by the handler (`spi_i`, `spi_r`, `token`, `session_id` on `openvpn`, `challenge`, and so on).
- Fixed-size byte arrays are JSON arrays of numbers 0–255. Today these are only the `bittorrent` fields `protocol_identifier`, `reserved`, `info_hash` and `peer_id`; show them as hex.
- Every other array of numbers is a list of IDs, not bytes: `cipher_suites` and `extensions` (`dtls`, uint16), `etypes` (`kerberos`), `encodings` (`rfb`, int32, can be negative). Show these as lists; joining them as hex gives wrong values.
- Nested objects (`header` on `smb` and `mongodb`, `questions` on `mdns`, `submessages` on `rtps`) are JSON objects or arrays of objects.

Array-of-frames `decoded` entries share these JSON names when the handler fills them: `direction`, `payload`, `command` (leaf operation), `path`, `status` (writes), `truncated`. Handler-specific fields sit beside them. A display that shows only the shared fields hides the most useful data for most handlers, so show every key a frame carries and use the per-handler page linked in the table below to order them. Some fields are easy to miss but matter for reading a session:

- `http`: `dest_port` and `src_port` on reads, because a session can span connections and ports while the top-level `dstPort`/`srcPort` belong to the first connection.
- `rdp`: `ntlm_domain`, `ntlm_user` and `ntlm_workstation` on the `NTLMAuthenticate` frame.
- `sip`: `from`, `to`, `call_id`, `username`, and `variant`/`visit` on writes.
- `jabber`, `smtp`, `opcua`, `mqtt`, `dicom`, `pop3`: `username` (and `password` on `jabber`).
- `dtls`, `jabber`: `server_name`.

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

| Handler | Transport | Details |
| --- | --- | --- |
| `http` | TCP | [protocols/http.md](protocols/http.md) |
| `tcp` | TCP | [protocols/tcp.md](protocols/tcp.md) |
| `udp` | UDP | [protocols/udp.md](protocols/udp.md) |
| `proxy_tcp`, `proxy_udp` | TCP/UDP | [protocols/proxy.md](protocols/proxy.md) |
| `sip` | TCP/UDP | [protocols/sip.md](protocols/sip.md) |
| `openvpn` | UDP | [protocols/openvpn.md](protocols/openvpn.md) |
| `mdns` | UDP | [protocols/mdns.md](protocols/mdns.md) |
| `l2tp` | UDP | [protocols/l2tp.md](protocols/l2tp.md) |
| `raknet` | UDP | [protocols/raknet.md](protocols/raknet.md) |
| `kerberos` | UDP | [protocols/kerberos.md](protocols/kerberos.md) |
| `ike` | UDP | [protocols/ike.md](protocols/ike.md) |
| `coap` | UDP | [protocols/coap.md](protocols/coap.md) |
| `a2s` | UDP | [protocols/a2s.md](protocols/a2s.md) |
| `ddp` | UDP | [protocols/ddp.md](protocols/ddp.md) |
| `rtps` | UDP | [protocols/rtps.md](protocols/rtps.md) |
| `wsdiscovery` | UDP | [protocols/wsdiscovery.md](protocols/wsdiscovery.md) |
| `knx` | UDP | [protocols/knx.md](protocols/knx.md) |
| `dtls` | UDP | [protocols/dtls.md](protocols/dtls.md) |
| `mqtt` | TCP | [protocols/mqtt.md](protocols/mqtt.md) |
| `memcache` | TCP | [protocols/memcache.md](protocols/memcache.md) |
| `modbus` | TCP | [protocols/modbus.md](protocols/modbus.md) |
| `dnp3` | TCP | [protocols/dnp3.md](protocols/dnp3.md) |
| `enip` | TCP | [protocols/enip.md](protocols/enip.md) |
| `opcua` | TCP | [protocols/opcua.md](protocols/opcua.md) |
| `mctp` | TCP | [protocols/mctp.md](protocols/mctp.md) |
| `dicom` | TCP | [protocols/dicom.md](protocols/dicom.md) |
| `mongodb` | TCP | [protocols/mongodb.md](protocols/mongodb.md) |
| `minecraft` | TCP | [protocols/minecraft.md](protocols/minecraft.md) |
| `socks` | TCP | [protocols/socks.md](protocols/socks.md) |
| `mcp` | TCP | [protocols/mcp.md](protocols/mcp.md) |
| `telnet` | TCP | [protocols/telnet.md](protocols/telnet.md) |
| `smtp` | TCP | [protocols/smtp.md](protocols/smtp.md) |
| `ftp` | TCP | [protocols/ftp.md](protocols/ftp.md) |
| `rfb` | TCP | [protocols/rfb.md](protocols/rfb.md) |
| `iscsi` | TCP | [protocols/iscsi.md](protocols/iscsi.md) |
| `bittorrent` | TCP | [protocols/bittorrent.md](protocols/bittorrent.md) |
| `jabber` | TCP | [protocols/jabber.md](protocols/jabber.md) |
| `pop3` | TCP | [protocols/pop3.md](protocols/pop3.md) |
| `whois` | TCP | [protocols/whois.md](protocols/whois.md) |
| `adb` | TCP | [protocols/adb.md](protocols/adb.md) |
| `smb` | TCP | [protocols/smb.md](protocols/smb.md) |
| `rdp` | TCP | [protocols/rdp.md](protocols/rdp.md) |

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
