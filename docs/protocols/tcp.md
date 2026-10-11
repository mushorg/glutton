# `tcp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `payload_hash`, `shellcode` (heuristic indicators matched in a read payload, when any), and on `tls-clienthello` / `tls-alert` reads `tls_version`, `cipher_suites`, `extensions`, `groups`, `sni`, `alpn`, `ja3`, `ja3n`, `ja4`, `ja4_r`. A completed or partial TLS termination adds a `write` with `status` `tls-handshake` holding the server flight (and any fatal alert).

## Session flow

Catch-all handler. A plaintext HTTP request (a known method token and its space, e.g. `GET `, `POST `, `PROPFIND `) never reaches it: the dispatcher routes HTTP on any port to the `http` handler (MCP paths to `mcp`), with or without Spicy. Each client message is one `read` frame (capped by `max_tcp_payload`) and gets one reply, for up to 4 messages per connection.

The connection ends with one of these `endReason` values:

- `max_frames`: the handler hangs up after the 4th message.
- The handler also hangs up after a reply that ends the session on a real service (`http`, which sends `Connection: close`) or after a silent one.
- `client_close`: the client closed after a reply. The handler waits for a next message, so a client that goes quiet ends with `timeout` instead.

## Choosing the reply

The reply is a canned service response from `protocols/tcp/banners` (from honeytrap, per mushorg/glutton#53). It is picked in this order:

1. **Payload signature.** Sets `command` on the read.
2. **Destination port.**
3. **Random bytes** otherwise.

Writes set `status` to the response name or `random`.

### Payload signatures

| Client sends | Response | Reply |
| --- | --- | --- |
| `SSH-` | `ssh` | SSH banner. The catch-all dispatcher routes `SSH-` to the [`ssh`](ssh.md) handler first, so this only applies when another dispatcher's fallback (e.g. `mctp`, `rtsp`) hands SSH to the catch-all |
| TLS handshake record (`16 03 00`–`04`, or TLCP `16 01 01` from GmSSL/Tongsuo) that is not a complete ClientHello | `tls-alert` | TLS alert |
| Complete TLS ClientHello | `tls-clienthello` | TLS handshake, see [TLS ClientHello](#tls-clienthello) |
| HTTP/2 client preface `PRI * HTTP/2.0` (h2c prior knowledge) | `http2-settings` | nginx-style SETTINGS, WINDOW_UPDATE, SETTINGS ACK and GOAWAY (NO_ERROR) on stream 0 |
| Oracle TNS CONNECT (packet type `01`, version 300–319, connect descriptor in the packet) | `tns-refuse` | Oracle 19c listener REFUSE (`ERR=12504`, `VSNNUM=318767104`), then the connection closes |
| X11 connection setup | `x11-denied` | Setup Failed reply "No protocol specified" in the client's byte order |
| LDAP root DSE search (empty base, scope baseObject) | `ldap-rootdse` | OpenLDAP-style SearchResultEntry plus SearchResultDone, echoing the messageID |
| Bitcoin mainnet P2P message (magic `f9 be b4 d9`, NUL-padded printable command) | `bitcoin-<command>` (`bitcoin` for an unlisted command) | `version` gets a Bitcoin Core 28.1 `version` (protocol 70016, current timestamp, start height grown from the 2024 halving, zeroed addresses) plus `verack`; a `ping` gets a `pong` with its nonce; other messages get no reply and the connection stays open |
| Niagara Fox hello (`fox a <n> -1 fox hello` header line) | `niagara-fox-hello` | Niagara AX 3.8 JACE station hello (`fox a 0 -1 fox hello`, QNX 6.5.0, a 192.168.1.x LAN address, `hostId`/`vmUuid`/`station.name` drawn once per run, empty BOG `sys.info`) |
| `MGLNDD_<ip>_<port>` scanner probe | `mglndd` | None |

### Port responses

| Port | Response | Notes |
| --- | --- | --- |
| 80 | `http` | Only for non-HTTP input; HTTP requests go to the `http` handler |
| 135 | `dcerpc-bind-ack` | |
| 139 | `netbios-session` | |
| 389 | `ldap` | Sends nothing, as an LDAP server does with input it cannot parse |
| 1433 | `mssql-prelogin` | Only on sensors without the `mssql` rule, and only for the first message; the next one (a LOGIN7) ends the session instead of getting the PRELOGIN reply again. A TDS PRELOGIN on any port goes to the [`mssql`](mssql.md) handler |
| 1911 | `niagara-fox` | Sends nothing and hangs up on bytes that are not a Fox hello (including Fox messages after the hello), as a Niagara station does before a session is open |
| 4444 | `cmd-shell` | See [Server-first banners](#server-first-banners) |
| 4899 | `radmin` | |
| 8009 | `ajp-404` | |
| 8126 | `statsd-stats` | Etsy statsd management console `stats` block ending in `END\n\n`, with uptime and `last_*` deltas from the clock |
| 8333 | `bitcoin` | Sends nothing and hangs up, as bitcoind does with bytes that are not its network magic |

Silent responses (`mglndd`, `ldap`, `bitcoin` on 8333, `niagara-fox` on 1911) leave only the `read` frame, with no `write`. A Bitcoin message that needs no answer (`verack`, `getaddr`, …) also leaves only its `read` frame, but the connection stays open for the next message. Clients that send nothing get no reply.

## TLS ClientHello

A complete ClientHello is tagged `tls-clienthello`. The handler then:

- finishes the handshake with the shared self-signed certificate (`helpers.TerminateTLSFrom`) and sets the event's `tls` object;
- records a `write` frame with `status` `tls-handshake` for the server's handshake flight (also when the client hangs up mid-handshake or crypto/tls sends a fatal alert);
- hands the session to the `http` handler when the first decrypted message is an HTTP request (HTTPS scanners on ports without a `tls:` rule). The produced event is then an `http` event with the `tls` object, and there is no `tcp` event and no `tls-clienthello` frame;
- otherwise answers the next decrypted client message exactly like a plaintext first message (signature, then port response, then random bytes);
- sends a server-first port banner inside the tunnel right after the handshake.

Frames after the handshake hold plaintext. A client that hangs up during or right after the handshake leaves the `tls-clienthello` read and the `tls-handshake` write (no top-level `tls` object when the handshake never completed).

### Fingerprint fields

A `tls-clienthello` read, and a `tls-alert` read that still parses, carries the hello's fingerprint. A truncated or malformed record has none of these fields.

| Field | Meaning |
| --- | --- |
| `tls_version` | Highest offered version |
| `cipher_suites`, `extensions`, `groups` | Decimal code points in wire order, GREASE kept |
| `sni`, `alpn` | Present only when sent |
| `ja3` | JA3 MD5 |
| `ja3n` | JA3 MD5 with extensions sorted (stable for clients that shuffle extension order, like Chrome) |
| `ja4` | FoxIO JA4 string |
| `ja4_r` | Raw JA4: sorted cipher and extension lists, signature algorithms in clear |

Parsing uses `helpers.ParseClientHello`, a lenient parser that reassembles a hello split over several records. It still fingerprints hellos crypto/tls rejects, such as duplicate extensions or an SNI with a trailing dot. Such a hello is tagged `tls-clienthello`; crypto/tls then fails the handshake with a `decode_error` alert, and the `tls-handshake` write holds that alert flight.

## Server-first banners

- **110 (`pop3`), 5900 (`rfb`):** banner sent on connect, before any read. 22 / 2222 (`ssh`) get the SSH banner the same way only without the `ssh` rule; the default rules send them to the [`ssh`](ssh.md) handler.
- **4444 (`cmd-shell`, a Windows Server 2003 `cmd.exe` prompt):** waits 2s for the client first.
  - A silent client gets the prompt as `decoded[0]` (a `write`).
  - A client that speaks first is routed by its bytes as on any catch-all port (HTTP to `http`), and otherwise gets the prompt as the reply.

After a greeting, the client's messages get random bytes unless a payload signature matches (no shell is emulated).

On 5900, a valid RFB ProtocolVersion reply is tagged `command` `rfb` and answered with the security handshake instead of random bytes (`status` `rfb-security`: `02 02 01` for 3.7/3.8, `00 00 00 02` for 3.3). The `rfb` handler (routed by default) takes the session further.

## RDP

RDP X.224 Connection Requests (any cookie length) never reach this handler: the catch-all routes them to `rdp` on any port.

Older sensors routed only 43-byte CRs, and only with Spicy enabled. Other off-port CRs got `random` writes, which is a handler artifact.

## Firebird

A Firebird `op_connect` (`00000001`, an attach/create/service-attach operation, connect version 2 or 3) never reaches this handler: the catch-all routes it to [`firebird`](firebird.md) on any port, and tcp/3050 has a `firebird` rule. Older sensors answered it with `random`, which is a handler artifact.

## ADB

An ADB transport `CNXN` (`434e584e`) never reaches this handler: the catch-all routes it to `adb` on any port. Older sensors answered off-port `CNXN` with `random`, which is a handler artifact.
