# `tcp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `payload_hash`, `shellcode` (heuristic indicators matched in a read payload, when any), and on `tls-clienthello` / `tls-alert` reads `tls_version`, `cipher_suites`, `extensions`, `groups`, `sni`, `alpn`, `ja3`, `ja3n`, `ja4`, `ja4_r`

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
| X11 connection setup | `x11-denied` | Setup Failed reply "No protocol specified" in the client's byte order |
| LDAP root DSE search (empty base, scope baseObject) | `ldap-rootdse` | OpenLDAP-style SearchResultEntry plus SearchResultDone, echoing the messageID |
| `MGLNDD_<ip>_<port>` scanner probe | `mglndd` | None |

### Port responses

| Port | Response | Notes |
| --- | --- | --- |
| 80 | `http` | Only for non-HTTP input; HTTP requests go to the `http` handler |
| 135 | `dcerpc-bind-ack` | |
| 139 | `netbios-session` | |
| 389 | `ldap` | Sends nothing, as an LDAP server does with input it cannot parse |
| 1433 | `mssql-prelogin` | |
| 4444 | `cmd-shell` | See [Server-first banners](#server-first-banners) |
| 4899 | `radmin` | |
| 8009 | `ajp-404` | |
| 8126 | `statsd-stats` | Etsy statsd management console `stats` block ending in `END\n\n`, with uptime and `last_*` deltas from the clock |

Silent responses (`mglndd`, `ldap`) leave only the `read` frame, with no `write`. Clients that send nothing get no reply.

## TLS ClientHello

A complete ClientHello is tagged `tls-clienthello`. The handler then:

- finishes the handshake with the shared self-signed certificate (`helpers.TerminateTLSFrom`) and sets the event's `tls` object;
- hands the session to the `http` handler when the first decrypted message is an HTTP request (HTTPS scanners on ports without a `tls:` rule). The produced event is then an `http` event with the `tls` object, and there is no `tcp` event and no `tls-clienthello` frame;
- otherwise answers the next decrypted client message exactly like a plaintext first message (signature, then port response, then random bytes);
- sends a server-first port banner inside the tunnel right after the handshake.

Frames after the handshake hold plaintext. A client that hangs up during or right after the handshake leaves only the `tls-clienthello` read.

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

Parsing uses `helpers.ParseClientHello`, a lenient parser that reassembles a hello split over several records. It still fingerprints hellos crypto/tls rejects, such as duplicate extensions or an SNI with a trailing dot. Such a hello is tagged `tls-clienthello`, crypto/tls then fails the handshake with a `decode_error` alert, and only the read frame remains.

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

## ADB

An ADB transport `CNXN` (`434e584e`) never reaches this handler: the catch-all routes it to `adb` on any port. Older sensors answered off-port `CNXN` with `random`, which is a handler artifact.
