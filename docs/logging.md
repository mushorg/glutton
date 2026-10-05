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

Events are emitted only when (1) `producers.enabled` is true so a producer object exists, (2) a handler calls `ProduceTCP(...)` or `ProduceUDP(...)`, (3) the matched rule does not set `produce: false`, and (4) at least one sink is enabled. Before output, configured `addresses` values are scrubbed from payload bytes (ASCII and UTF-16LE) and replaced with `1.2.3.4`. The same sanitizer runs on every string and byte slice inside `decoded` (frame fields such as `from`, `to`, `endpoint_url`, nested structs, maps), so the sensor address never appears in decoded output; fixed-size byte arrays are left alone. Events produced before this change only scrubbed `payload` and `path`.

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
| `tcp` | Array of per-direction frames: `direction`, `command`, `status`, `payload`, `payload_hash` | Catch-all. Client bytes are one `read` frame (capped by `max_tcp_payload`). The reply is a canned service response (`protocols/tcp/banners`, from honeytrap per mushorg/glutton#53): a payload signature wins (`SSH-` → `ssh` banner, TLS record → `tls-alert`) and sets `command` on the read; otherwise the destination port picks it (80 `http`, 135 `dcerpc-bind-ack`, 139 `netbios-session`, 1433 `mssql-prelogin`, 4899 `radmin`, 8009 `ajp-404`); otherwise random bytes. Writes set `status` to the response name or `random`. Ports 22/2222 (`ssh`), 110 (`pop3`) and 5900 (`rfb`) get their banner on connect, before any read. Clients that send nothing get no reply. |
| `udp` | Array of read frames: `direction`, `payload`, `payload_hash`, `truncated` | Catch-all. One datagram per event (capped at 1024 bytes). `truncated` is set when the datagram was longer. The handler does not reply. Datagrams with RakNet offline magic are rerouted to `raknet`; APPLICATION 10/12 Kerberos AS-REQ/TGS-REQ are rerouted to `kerberos`; CoAP version-1 GET/POST/PUT/DELETE datagrams are rerouted to `coap`; IKE headers whose length field equals the datagram length (optionally after the 4-byte non-ESP marker) are rerouted to `ike`. |
| `proxy_tcp`, `proxy_udp` | Per-direction entries: `direction`, `payload`, `payload_hash`, `bytes`, `truncated` | Only when `capture_traffic.enabled` is true. Samples are capped by `max_tcp_payload`; `truncated` is whether more bytes were forwarded than captured. `proxy_udp` emits one event per flow when the flow idles out or closes. |
| `sip` (TCP/UDP) | Array of per-direction frames: `direction`, `command`, `path`, `status`, `from`, `to`, `call_id`, `user_agent`, `username`, `payload`, `truncated` | `command` is the SIP method and `path` the Request-URI on reads. Writes set `status`: `200` for OPTIONS, REGISTER (with or without credentials) and BYE; `100`, `180`, then `200` with an SDP answer for INVITE, so toll-fraud scanners go on to dial and the number shows up in `path`; `401` challenge then `403` after credentials for SUBSCRIBE/MESSAGE/NOTIFY/PUBLISH/REFER/UPDATE/INFO; `481` CANCEL/PRACK; `501` unknown. The top `Via` of each response gets `received=<source IP>` when the client asked for `rport` or its sent-by host differs from the packet source, and a valueless `rport` is filled with the source port (RFC 3261 §18.2.1, RFC 3581). `user_agent` is the client User-Agent on reads and the honeypot Server header on writes. `username` is the digest Authorization username; the digest response is not copied into `decoded`. UDP sets `truncated` when a datagram exceeded 4096 bytes. |
| `openvpn` (UDP) | Array of read frames: `direction`, `command`, `opcode`, `opcode_name`, `key_id`, `session_id` (hex), `payload`, `truncated` | `command` copies `opcode_name`. The handler does not reply. |
| `mdns` (UDP) | Array of read frames: `direction`, `command`, `path`, `questions` (`qname`, `qtype`, `qtype_name`, `qclass`), `payload`, `truncated` | `command`/`path` are the first question's qtype name and qname. The handler does not reply. |
| `l2tp` (UDP) | Array of per-direction frames: `direction`, `command`, `status`, `message_type`, `message_name`, `host_name`, `vendor_name`, `tunnel_id`, `assigned_tunnel_id`, `ns`, `nr`, `payload`, `truncated` | `command` copies `message_name`. SCCRQ probes get a `write` frame with `status` `SCCRP`. |
| `raknet` (UDP) | Array of read frames: `direction`, `command`, `packet_id`, `packet_name`, `protocol`, `magic_ok`, `mtu`, `payload`, `truncated` | `command` copies `packet_name`. Parse-only; no Open Connection Reply or Unconnected Pong. `0x05` OCR1 sets `protocol` (byte after magic) and `mtu` (datagram length). Generic UDP peeks the same magic and reroutes here. |
| `kerberos` (UDP) | Array of read frames: `direction`, `command`, `path`, `msg_type`, `msg_name`, `pvno`, `realm`, `sname`, `cname`, `etypes`, `from`, `nonce`, `payload`, `truncated` | `command` copies `msg_name`; `path` copies `sname`. Parse-only; no KRB-ERROR or AS-REP. Truncated or non-DER datagrams still emit a frame with raw `payload` (`msg_name` `UNKNOWN`). Generic UDP peeks APPLICATION 10/12 and reroutes here. |
| `ike` (UDP) | Array of per-direction frames: `direction`, `command`, `status`, `version`, `spi_i`, `spi_r` (hex), `encryption`, `prf`, `integrity`, `dh_groups`, `ke_group`, `notifies`, `vendor_ids` (hex), `nat_t`, `payload`, `truncated` | udp/500 and udp/4500 (`nat_t` when the non-ESP marker is present; replies keep it). `command` is the exchange name. Reads list every offered transform name (key length suffixed, e.g. `AES_CBC_256`); IKEv1 records header and Vendor IDs only, without a reply. IKEv2 IKE_SA_INIT requests get a stateless reply: `INVALID_KE_PAYLOAD` asking for MODP_2048/ECP_256/ECP_384 when the KE group differs, a full IKE_SA_INIT (chosen transforms, random KE and nonce) when it matches, or `NO_PROPOSAL_CHOSEN`. Writes set `status` and list the chosen transforms. Datagrams over 4096 bytes are capped with `truncated`. |
| `coap` (UDP) | Array of per-direction frames: `direction`, `command`, `status`, `type`, `code`, `code_name`, `message_id`, `token` (hex), `path`, `observe`, `payload`, `truncated` | `command` copies `code_name`. Writes also set `status` (`CONTENT` / `CREATED` / `DELETED`). GET `.well-known/core` returns CoRE Link Format `</ps/temp>,</ps/hum>`. Generic UDP peeks version-1 request codes 1–4 and reroutes here. |
| `mqtt` (TCP) | Array of per-direction frames: `direction`, `command`, `packet`, `client_id`, `username`, `topic`, `topics`, `qos`, `payload` | `command` copies `packet`. CONNECT gets CONNACK accept; password bytes are not copied into `decoded`. |
| `memcache` (TCP) | Array of per-direction frames: `direction`, `command`, `status`, `payload` | Writes set `status` (`STORED`, `END`, `ERROR`, `CLIENT_ERROR`, `VERSION`). `set` frames aggregate the command line plus the data chunk. |
| `modbus` (TCP) | Array of per-direction frames: `direction`, `command`, `function_code`, `unit_id`, `address`, `quantity`, `status`, `payload` | `command` copies `function_code`. Exception writes set `status` `Exception`. |
| `opcua` (TCP) | Array of per-direction frames: `direction`, `command`, `path`, `message_type`, `service`, `endpoint_url`, `security_policy`, `application_uri`, `application_name`, `username`, `payload` | `command` is `service` (or `message_type` if empty). `path` copies `endpoint_url`. Username identity is recorded; password bytes are not copied into `decoded`. |
| `mctp` (TCP) | Array of per-direction frames: `direction`, `command`, `method`, `cseq`, `func_version`, `segments`, `status`, `return_code`, `payload`, `truncated` | HiSilicon DVR control protocol (tcp/9000). `command` is the `HI_SRDK_*` function, `method` the request method (`REMOTE`), `segments` the number of body data segments. Writes set `status` `200` and `return_code` `0`. Bodies over 64 KiB are stored up to the cap with `truncated`. Non-MCTP traffic on the port falls back to `tcp`. |
| `dicom` (TCP) | Array of per-direction frames: `direction`, `command`, `path`, `status`, `pdu_type`, `called_ae`, `calling_ae`, `application_context`, `abstract_syntaxes`, `transfer_syntaxes`, `implementation_class_uid`, `implementation_version`, `username`, `message_id`, `sop_class_uid`, `sop_instance_uid`, `move_destination`, `payload_hash`, `payload`, `truncated` | DICOM Upper Layer (tcp/104, tcp/11112). `command` is the DIMSE command (`C-ECHO-RQ`, `C-FIND-RQ`, `C-STORE-RSP`, ...) for P-DATA-TF frames and the PDU name (`A-ASSOCIATE-RQ`, `A-RELEASE-RP`, `A-ABORT`) otherwise. `path` copies `called_ae`. Every association is accepted; C-ECHO/C-FIND/C-STORE/C-GET/C-MOVE writes set `status` `Success`, N-* services `UnrecognizedOperation`. A DIMSE message's command and data set PDUs are aggregated into one read frame (capped at 1 MiB with `truncated`); C-STORE data sets are stored under `payloads/dicom` and hashed into `payload_hash`. User identity usernames are recorded; passcodes are not copied into `decoded`. |
| `mongodb` (TCP) | Array of per-direction frames: `direction`, `header`, `opcode_str`, `command`, `status`, `payload` | `command` is the BSON command name. Writes set `status` `ok`. |
| `mcp` (TCP) | Array of per-direction frames: `direction`, `command`, `path`, `status`, `session_id`, `payload` | `command` is the JSON-RPC method or HTTP verb. Writes set HTTP `status`. Shares the idle session table with HTTP. |
| `telnet` (TCP) | Array of per-direction frames: `direction`, `command`, `path`, `message`, `payload_hash` | Login reads set `command` `username`/`password`; shell reads use the first token. `wget`/`curl` lines set `path` to the http(s) URL and `payload_hash` when the sample fetch succeeds. IAC negotiation is a separate `read` frame with no command. Process log: Info `telnet login` with `src_ip`/`src_port`/`dest_port`/`username`/`password`; shell lines at Debug. |
| `smtp` (TCP) | Array of per-direction frames: `direction`, `command`, `status`, `payload` | Reads set `command` to the SMTP verb. Writes set `status` to the 3-digit reply code. |
| `ftp` (TCP) | Array of per-direction frames: `direction`, `command`, `path`, `status`, `payload`, `payload_hash` | `command` is the FTP verb. STOR/RETR set `path`. Writes set `status` to the numeric reply code. |
| `rfb` (TCP) | Array of per-direction frames: `direction`, `command`, `payload` | `command` is `ProtocolVersion`, `Security`, `ServerInit`, or `ClientInit`. |
| `iscsi` (TCP) | Array of per-direction frames: `direction`, `command`, `message`, `payload` | `command` is the opcode name (`LOGIN_REQUEST`, `LOGIN_RESPONSE`, …). One produced event per TCP session. |
| `bittorrent` (TCP) | Array of per-direction frames: `direction`, `command`, `message`, `payload`, `truncated` | `command` is `handshake`. |
| `jabber` (TCP) | Array of per-direction frames: `direction`, `command`, `path`, `status`, `mechanism`, `username`, `password`, `tls`, `server_name`, `payload`, `truncated` | XMPP client-to-server (tcp/5222, tcp/5223). The honeypot waits for the client (no banner). Frames are split per stanza, not per line. Reads set `command` to the element name (`stream`, `starttls`, `auth`, `iq`, `message`, `stream-end`, ...) and `path` to the stream `to` attribute. Writes use `stream` (header, `path` is `from`), `features` (PLAIN + legacy iq-auth, plus STARTTLS before TLS), `proceed`, `failure`, `iq`, `stream-error`, and `stream-end`; `status` is the condition (`not-authorized`, `invalid-mechanism`, `not-well-formed`, `policy-violation`, `proceed`, `result`). SASL PLAIN `auth` and `jabber:iq:auth` set reads record `username`/`password` (never validated; auth always fails and the stream is closed). A first byte `0x16` (direct TLS, tcp/5223) or STARTTLS adds a `tls` read frame with the raw ClientHello in `payload` and SNI in `server_name`; later frames set `tls` and carry decrypted XML. Frames are capped at 4 KiB (`truncated`) and sessions at 32 reads. Non-XML input is stored as one read frame without `command`. |
| `adb` (TCP) | Array of read frames: `direction`, `command`, `payload`, `truncated` | `command` is the service prefix before `:`. Bodies longer than 255 bytes are clipped with `truncated`. |
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
