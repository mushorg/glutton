# `tcp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `payload_hash`, `shellcode` (heuristic indicators matched in a read payload, when any), `password` (a credential guess a signature parsed from the read, in plaintext: the KMP login PIN), and on `tls-clienthello` / `tls-alert` reads `tls_version`, `cipher_suites`, `extensions`, `groups`, `sni`, `alpn`, `ja3`, `ja3n`, `ja4`, `ja4_r`. A completed or partial TLS termination adds a `write` with `status` `tls-handshake` holding the server flight (and any fatal alert). When a handshake write failed, that frame also has `error` (`reply over budget` when the `tcp_reply_limit` guard dropped it, otherwise `write failed`) and may have no `payload`.

## Session flow

Catch-all handler. A plaintext HTTP request (a known method token and its space, e.g. `GET `, `POST `, `PROPFIND `) never reaches it: the dispatcher routes HTTP on any port to the `http` handler (MCP paths to `mcp`), with or without Spicy. Each client message is one `read` frame (capped by `max_tcp_payload`) and gets one reply, for up to 4 messages per connection.

The connection ends with one of these `endReason` values:

- `max_frames`: the handler hangs up after the 4th message.
- The handler also hangs up after a reply that ends the session on a real service (`http`, which sends `Connection: close`) or after a silent one.
- `client_close`: the client closed after a reply. The handler waits for a next message, so a client that goes quiet ends with `timeout` instead.

## Choosing the reply

The reply is a canned service response from `protocols/tcp/banners` (from honeytrap, per mushorg/glutton#53). It is picked in this order:

1. **Payload signature.** Sets `command` on the read. Every signature is checked; if more than one matches, one of them is picked at random.
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
| LDAP simple BindRequest, anonymous (empty name and password) | `ldap-bind` | BindResponse `success`, echoing the messageID |
| LDAP simple BindRequest with a name or password | `ldap-bind-invalid` | BindResponse `invalidCredentials` (49), echoing the messageID; the credentials are in the `read` frame |
| Bitcoin mainnet P2P message (magic `f9 be b4 d9`, NUL-padded printable command) | `bitcoin-<command>` (`bitcoin` for an unlisted command) | `version` gets a Bitcoin Core 28.1 `version` (protocol 70016, current timestamp, start height grown from the 2024 halving, zeroed addresses) plus `verack`; a `ping` gets a `pong` with its nonce; other messages get no reply and the connection stays open |
| Litecoin mainnet P2P message (magic `fb c0 b6 db`, same framing as Bitcoin) | `litecoin-<command>` (`litecoin` for an unlisted command) | `version` gets a Litecoin Core 0.21.4 `version` (protocol 70015, MWEB service bit, current timestamp, start height grown from the August 2023 halving at 2.5 minutes per block, zeroed addresses) plus `verack`; a `ping` gets a `pong` with its nonce; other messages get no reply and the connection stays open |
| Niagara Fox hello (`fox a <n> -1 fox hello` header line) | `niagara-fox-hello` | Niagara AX 3.8 JACE station hello (`fox a 0 -1 fox hello`, QNX 6.5.0, a 192.168.1.x LAN address, `hostId`/`vmUuid`/`station.name` drawn once per run, empty BOG `sys.info`) |
| TeamViewer `CMD_PING` (`17 24 10`, LE u16 length, body; Shodan sends `17 24 10 04 00 00 00 00 00`) | `teamviewer-pingok` | `CMD_PINGOK` `17 24 11 04 00 00 00 00 00` |
| TACACS+ AUTHEN START (`c0`/`c1` `01 01`, flags, session_id, u32 body length equal to the bytes after the header; Shodan sends the header alone) | `tacacs-authen-error` | tac_plus F4.0.4 AUTHEN REPLY: client's version and session_id, seq 2, flags 0, status ERROR ("Invalid AUTHEN/START packet (too short)" or "(check keys)") encrypted with a random per-process key, then the connection closes |
| PJL command (`@PJL ...`, optionally after the `1b 25 2d 31 32 33 34 35 58` UEL; Shodan sends `@PJL INFO STATUS`, nmap `@PJL INFO ID`) | `pjl` | HP LaserJet Pro M404dn: `INFO ID` gets the quoted model, `INFO STATUS` gets `CODE=10001 DISPLAY="Ready" ONLINE=TRUE`, other commands are echoed; replies end with a form feed |
| WebLogic T3 hello (`t3 <version>\nAS:..\nHL:..\n\n`) | `weblogic-t3` | Replies `HELO:12.2.1.4.0.false\nAS:2048\nHL:19\n\n` (format from public T3 tooling, unverified); later T3 frames are recorded |
| NoMachine client version line `NXSH-<dotted version>` + LF or CRLF (nmap's NoMachine probe sends `NXSH-5.6.7\n` to tcp/4000) | `nomachine-nx` | NoMachine 9.7.3 nxd version line `NXD-9.7.3\n` (nmap `nomachine-nx`); later client messages are recorded |
| ZooKeeper four-letter command `srvr` (also `stat`/`stats`, which nmap's `stats\r\n` probe reaches; bare command only) | `zookeeper-srvr` | ZooKeeper 3.6.3 standalone `srvr` block (`Zookeeper version:` … `Node count: 5`, bare LF; version and build strings unverified); the connection closes after the reply |
| Xiongmai/HiSilicon DVR backdoor `OpenTelnet:OpenOnce` (bare, as Shodan sends it, or with the public PoC's 1-byte length prefix; trailing NUL/CR/LF allowed) | `xiongmai-randnum` | `randNum:` + 8 random decimal digits, the macGuarder/dvrHelper challenge (no terminator); the challenge is never verified, see port 9530 |
| Erlang epmd `NAMES_REQ` (exactly `00 01 6e`, nmap's `epmd` probe; Shodan sends it to tcp/4369) | `epmd-names` | RabbitMQ broker's epmd: port `00 00 11 11` then `name rabbit at port 25672\n`; the connection closes after the reply |
| Erlang epmd `PORT_PLEASE2_REQ` (`00 <len> 7a <node name>`, length covering the rest) | `epmd-port2` | `PORT2_RESP` for `rabbit` (port 25672, normal node, TCP, distribution versions 6..5, no extra) or result `1` (not found) for any other name; the connection closes after the reply |
| SAProuter message without its NI length prefix (`ROUTER_ADM\0`, `NI_ROUTE\0`, `NI_PING\0`; Shodan sends a bare 35-byte `ROUTER_ADM` info request to tcp/3299) | `saprouter-too-big` | `NI_RTERR` "Network packet too big" (rc -93) quoting the first 4 bytes as the rejected NI length (`NiBufIIn: message length 1380930900 exceeds max (10024)` for `ROUT`), with the current time and a per-run host in `SAProuter 40.4 (SP3) on '<host>'`; the connection closes after the reply |
| Kamstrup Meter Protocol GetRegister (KMP, tcp/1025: `80`, address `3f`, CID `10`, count, BE u16 register IDs, CRC-16/CCITT, `0d`, with `06 0d 1b 40 80` stuffed as `1b <b^ff>`; the read must be only complete CRC-valid frames, several may be pipelined; Shodan reads registers 1, 2, 13, 14, 1054, 1055) | `kamstrup-getregister` | One `40 3f 10` reply per frame with unit, length, SiEx and value for each known register (energy import/export in kWh at 0.1 and 0.0001 resolution, voltage L1/L2); import grows from a per-run base with a per-run load, voltage jitters 226..235 V; unknown registers are left out |
| KMP login (CID `92`, BE u16 PIN) | `kamstrup-login` | `40 3f 92 01` (denied); the PIN is recorded as `password` on the read |
| A CRC-valid KMP frame for another address or command | `kamstrup` | None, the connection stays open |
| `MGLNDD_<ip>_<port>` scanner probe | `mglndd` | None |

### Port responses

| Port | Response | Notes |
| --- | --- | --- |
| 49 | `tacacs` | Sends nothing, as tac_plus does with a bad header; AUTHEN STARTs get `tacacs-authen-error` |
| 80 | `http` | Only for non-HTTP input; HTTP requests go to the `http` handler |
| 135 | `dcerpc-bind-ack` | |
| 139 | `netbios-session` | |
| 389 | `ldap` | Sends nothing, as an LDAP server does with input it cannot parse |
| 1433 | `mssql-prelogin` | Only on sensors without the `mssql` rule, and only for the first message; the next one (a LOGIN7) ends the session instead of getting the PRELOGIN reply again. A TDS PRELOGIN on any port goes to the [`mssql`](mssql.md) handler |
| 3299 | `saprouter-timeout` | `NI_RTERR` "connection timed out" (rc -5, `no route received within 5s`), which nmap reports as `SAProuter 40.4 SP3`: sent to a client that stays silent for 2s, or as the reply to bytes that match no signature; the connection closes after it |
| 4369 | `epmd` | Sends nothing and closes, as epmd does with a request it cannot parse; `NAMES_REQ` and `PORT_PLEASE2_REQ` get `epmd-names` / `epmd-port2` |
| 1911 | `niagara-fox` | Sends nothing and hangs up on bytes that are not a Fox hello (including Fox messages after the hello), as a Niagara station does before a session is open |
| 4444 | `cmd-shell` | See [Server-first banners](#server-first-banners) |
| 4899 | `radmin` | |
| 5938 | `teamviewer-identify` | See [Server-first banners](#server-first-banners) |
| 8009 | `ajp-404` | |
| 8126 | `statsd-stats` | Etsy statsd management console `stats` block ending in `END\n\n`, with uptime and `last_*` deltas from the clock |
| 8333 | `bitcoin` | Sends nothing and hangs up, as bitcoind does with bytes that are not its network magic |
| 9333 | `litecoin` | Sends nothing and hangs up, as litecoind does with bytes that are not its network magic |
| 9530 | `xiongmai-9530` | Xiongmai macGuarder/dvrHelper backdoor port. `OpenTelnet:OpenOnce` gets `xiongmai-randnum`; anything else, including the client's challenge answer, is recorded without a reply and the connection stays open (a real device's failure string is not public) |
| 21379 | `opc-tunneller` | MatrikonOPC Tunneller default port. Sends nothing but keeps the connection open, so the client hello and its follow-up frames are recorded; the real server's reply framing is not public |

Silent responses (`mglndd`, `tacacs` on 49, `ldap`, `bitcoin` on 8333, `litecoin` on 9333, `niagara-fox` on 1911) leave only the `read` frame, with no `write`. A Bitcoin or Litecoin message that needs no answer (`verack`, `getaddr`, …) also leaves only its `read` frame, but the connection stays open for the next message, as does every message on 21379 (`opc-tunneller`), a KMP frame the meter does not answer (`kamstrup`) and a post-TLS `tls-probe` (CR/LF only). Clients that send nothing get no reply.

## TLS ClientHello

A complete ClientHello is tagged `tls-clienthello`. The handler then:

- finishes the handshake with the shared self-signed certificate (`helpers.TerminateTLSFrom`) and sets the event's `tls` object;
- records a `write` frame with `status` `tls-handshake` for the server's handshake flight (also when the client hangs up mid-handshake or crypto/tls sends a fatal alert). If a handshake write fails, the frame is still recorded, with an `error` field (`reply over budget` for a `tcp_reply_limit` drop, otherwise `write failed`) and only the bytes that went out, and the event's `endReason` is `write_error`;
- hands the session to the `http` handler when the first decrypted message is an HTTP request (HTTPS scanners on ports without a `tls:` rule). The produced event is then an `http` event with the `tls` object, and there is no `tcp` event and no `tls-clienthello` frame;
- otherwise answers the next decrypted client message exactly like a plaintext first message (signature, then port response, then random bytes), except a lone CR/LF probe (`\n`, `\r\n`, …) is tagged `tls-probe` and gets no reply, as a real HTTPS server waiting for a request line would;
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
- **5938 (`teamviewer-identify`, a TeamViewer `CMD_IDENTIFY` that nmap `-sV` reports as `TeamViewer`):** waits 2s for the client first, like 4444. Bytes 5–8 are random per connection. A `CMD_PING` (Shodan) is answered with `teamviewer-pingok` whether or not the greeting was sent. Other client bytes get `CMD_IDENTIFY` once, and the next message ends the session.

After a greeting, the client's messages get random bytes unless a payload signature matches (no shell is emulated).

On 5900, a valid RFB ProtocolVersion reply is tagged `command` `rfb` and answered with the security handshake instead of random bytes (`status` `rfb-security`: `02 02 01` for 3.7/3.8, `00 00 00 02` for 3.3). The `rfb` handler (routed by default) takes the session further.

## RDP

RDP X.224 Connection Requests (any cookie length) never reach this handler: the catch-all routes them to `rdp` on any port.

Older sensors routed only 43-byte CRs, and only with Spicy enabled. Other off-port CRs got `random` writes, which is a handler artifact.

## Firebird

A Firebird `op_connect` (`00000001`, an attach/create/service-attach operation, connect version 2 or 3) never reaches this handler: the catch-all routes it to [`firebird`](firebird.md) on any port, and tcp/3050 has a `firebird` rule. Older sensors answered it with `random`, which is a handler artifact.

## SPICE

A SPICE link message (`REDQ` magic) never reaches this handler: the catch-all routes it to [`spice`](spice.md) on any port except 5900, where it sends the RFB banner first. The `rfb` rule on 5900-5910 hands SPICE clients to `spice` too. Older sensors answered it with `random`, which is a handler artifact.

## Redis

A RESP multibulk request (`*N\r\n$`, as sent by redis-cli, client libraries and nmap) never reaches this handler: the catch-all routes it to [`redis`](redis.md) on any port, and tcp/6379 has a `redis` rule. Inline commands (`INFO\r\n`) stay here off-port, since they cannot be told apart from other text consoles. Older sensors answered RESP with `random`, which is a handler artifact.

## ADB

An ADB transport `CNXN` (`434e584e`) never reaches this handler: the catch-all routes it to `adb` on any port. Older sensors answered off-port `CNXN` with `random`, which is a handler artifact.
