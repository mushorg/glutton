# `http` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

Glutton has two `http` handlers: the Go handler (default) and a Spicy-based one. Both emit per-direction frames and emulate the same applications (Selenium Grid, Citrix); they differ in session grouping and which header-derived fields they decode. See [Spicy differences](#http-spicy).

## `http` (Go)

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `query`, `parameters`, `host`, `username`, `password`, `user_agent`, `ja4h`, `status`, `browser`, `binary`, `args`, `truncated`, `citrix`, `log4shell`, `php2shell`, `plex2shell`, `session_id`, `dest_port`, `src_port`, `payload`

### Frame fields

| Field | Set on | Meaning |
| --- | --- | --- |
| `command` | reads | HTTP method. |
| `query` | reads | Raw query string. |
| `parameters` | reads | Parsed query map. |
| `ja4h` | reads | [FoxIO JA4H](https://github.com/FoxIO-LLC/ja4) client fingerprint `a_b_c_d`, computed from the raw request (method, version, cookie/referer flags, header count and language; hashes of header order, sorted cookie names and cookie values). Empty when the request line did not parse. |
| `dest_port`, `src_port` | reads | Ports of the connection the frame arrived on (see [Sessions](#sessions)). |
| `status` | writes | Response status, e.g. `200`. |
| `username`, `password` | reads | `Authorization: Basic` credentials, or the Proxmox VE ticket login form (see [Emulated applications](#emulated-applications)). |
| `browser`, `binary`, `args`, `citrix`, `log4shell`, `php2shell`, `plex2shell`, `truncated` | reads | Application-specific; see [Emulated applications](#emulated-applications). |

### Sessions

The handler speaks keep-alive HTTP and groups frames across TCP connections into one produced event:

- Every response sets a `session` cookie. Frames that share that cookie (per source host) are grouped into one event, produced when the session idles out (`conn_timeout`).
- Requests without the cookie (most scanners) join the source IP's latest live session, across connections and destination ports.
- Because one event can span several connections, the top-level `dstPort`/`srcPort` are those of the first connection; each read frame carries its own `dest_port`/`src_port`.
- A source session stops accepting new cookieless connections after 500 frames or one hour.
- The idle session table is shared with [`mcp`](mcp.md).

### Emulated applications

#### Selenium Grid 4

Package: `protocols/tcp/selenium`. Every path on tcp/4444, and `/wd/hub/*` on any port, is answered as an unauthenticated Grid.

| Request | Response |
| --- | --- |
| `/status` | Ready JSON |
| `/` | `302` → `/ui/` |
| `/graphql` | Grid fields |
| `POST /session` | `500 session not created` (Chrome "exited normally"), so no session exists |
| Other paths | `404 unknown command` |

`POST /session` reads set `browser`, `binary`, and `args`, taken from `goog:chromeOptions`, `moz:firefoxOptions`, or `ms:edgeOptions`. Caps: 64 args of 4 KiB each and a 1 KiB binary; `truncated` is set when anything is cut.

#### Proxmox VE

Package: `protocols/tcp/pve`. Every path on tcp/8006 is answered as a `pveproxy` node (`Server: pve-api-daemon/3.0`).

| Request | Response |
| --- | --- |
| `GET /` | Login page titled with the node name |
| `POST /api2/json/access/ticket` | `401 authentication failure`, body `{"data":null}` |
| Other `/api2/*` | `401 No ticket` |
| Anything else | `404` |

Ticket reads set `username` from the form `username` field, with `@realm` appended when `realm` is sent separately, and `password` from the form `password` field (both capped at 256 bytes).

The default rule terminates TLS on tcp/8006 (`tls: auto`) with a node certificate signed by a per-sensor `PVE Cluster Manager CA`, so the event carries a `tls` object.

#### Rapid7 Nexpose / InsightVM console

The default rule also terminates TLS on tcp/3780 (`tls: auto`, default self-signed certificate), the port of the Nexpose / InsightVM Security Console. There is no dedicated persona: requests get the generic responses. A client that sends only blank lines gets no reply, the way an HTTPS server waits for a request line.

#### Citrix ADC / NetScaler Gateway (CVE-2019-19781)

Package: `protocols/tcp/citrix`. Reads on the exploit chain set `citrix` to `{stage, nsc_user, template, truncated}`.

| `stage` | Request | Response |
| --- | --- | --- |
| `login` | `/vpn/`, `/vpn/index.html` | `200` NetScaler Gateway login page |
| `probe` | `/vpn/../vpns/` | `403 Forbidden` |
| `smb_conf` | `/vpn/../vpns/cfg/smb.conf` | `200` fake `smb.conf` |
| `template_write` | `POST /vpn/../vpns/portal/scripts/newbm.pl` | `200` `parent.window.ns_reload` page |
| `template_fetch` | `/vpn/../vpns/portal/<file>.xml` | `200` empty |
| `traversal` | Other `/vpns/` traversal | `200` empty |

Matching rules:

- `%2e%2e` and `%2f` are decoded before matching.
- `/vpns/` paths without a `..` segment are not tagged.

On `template_write`:

- `nsc_user` is the `NSC_USER` header: the bookmark file name, usually a `../` path into `portal/templates/`. Capped at 256 B.
- `template` is the form `title` field: the injected Template Toolkit payload. Capped at 4 KiB.
- `truncated` is set when either is cut.

> **Change (2026-10-10):** before this date, every `/vpn/*` request got the `smb.conf` reply (with a wrong `Content-Length`), and the `newbm.pl` POST got no reply.

#### Log4Shell (CVE-2021-44228)

Package: `protocols/tcp/log4shell`. Parse-only: a read whose request line, headers or body contains a JNDI lookup sets `log4shell` to `{lookups, truncated}`. The reply is whatever the request would get anyway; Glutton never resolves or dials the lookup host.

Each lookup is `{location, raw, resolved}`:

- `location` is `path`, `query`, `body` or `header:<Name>` (User-Agent, X-Api-Version, ...).
- `raw` is the `${...}` expression as sent, after URL-decoding.
- `resolved` is the expression with `lower:`, `upper:` and `name:-default` lookups evaluated (`${${lower:j}ndi:...}`, `${${::-j}${::-n}di:...}`); it is omitted when identical to `raw`.

Caps: 16 lookups per request, 512 B per expression, 16 KiB scanned per field or body; `truncated` is set when any applies. The Spicy `http` handler does not set `log4shell`.

#### PHP2Shell (CVE-2026-109618, CVE-2026-109619)

Package: `protocols/tcp/php2shell`. Parse-only: a `multipart/form-data` read that matches at least one indicator sets `php2shell` to `{indicators, parts, content_length, boundary, max_depth, truncated}`. The reply is whatever the request would get anyway. Public reporting names multipart parsing as the only known trigger but publishes no exploit bytes, so the indicators are request-shape heuristics plus the probe shape of the public [Assetnote scanner](https://github.com/assetnote/php2shell-scanner) (`POST /index.php`, `boundary=` empty, LF-only parts named `a[]` plus 62 `[a]` levels, 1/8/20 MiB). A plain file upload is not tagged.

| `indicators` | Meaning |
| --- | --- |
| `upload_progress` | Body contains the `PHP_SESSION_UPLOAD_PROGRESS` field (the memory-disclosure path). |
| `many_parts` | At least 100 multipart parts. |
| `large_body` | Declared `Content-Length` or received body of at least 1 MiB. |
| `long_session_cookie` | `PHPSESSID` cookie value longer than 256 B. |
| `empty_boundary` | `boundary=` is present but empty (RFC 2046 requires 1–70 chars); parts are then counted on bare `--`. |
| `nested_name` | A part name nested at least 32 array levels (`max_depth` holds the deepest seen). |
| `scanner_user_agent` | `User-Agent` contains `PHP2Shell/`. |

`parts` and `max_depth` cover the first 1 MiB of the body; bodies over 1 MiB are not read, so the scanner's 8 and 20 MiB probes are tagged from headers alone (`empty_boundary`, `large_body`, `scanner_user_agent`); `content_length` is the larger of the declared and received size; `boundary` is capped at 128 B. `truncated` is set when either cap applies. The Spicy `http` handler does not set `php2shell`.

#### Plex2Shell (CVE-2026-96652, -96654, -96655, -96656)

Package: `protocols/tcp/plex2shell`. Every path on tcp/32400 is answered as an unclaimed Plex Media Server older than the fix (1.43.3.10861), and a tagged request on any other port gets the same reply. The only public request bytes are one honeypot log line, so the tags are heuristics on that shape, not signatures. The callback host is recorded and never resolved or dialed.

| Request | Response |
| --- | --- |
| `GET /identity` | `200` XML `MediaContainer` with a per-sensor `machineIdentifier` and a vulnerable `version` |
| `GET /player/timeline/(un)subscribe` | `200` `<Response code="200" status="OK" />` |
| Anything else | `401 Unauthorized` |

The reply bodies are best recollection of a real server, not captures. A read that matches at least one indicator sets `plex2shell` to `{indicators, callback_host, callback_ip, callback_port, agent, client_identifier, truncated}`:

| `indicators` | Meaning |
| --- | --- |
| `subscribe_path` | Path is `/player/timeline/subscribe`. |
| `loopback_prefix_host` | A query or `X-Plex-*` value holds a host that starts with a loopback literal and has more labels (`127.0.0.1.<ip>.sslip.io:8952`). Plain `127.0.0.1:32400` is not tagged. |
| `agent_callback` | A `com.plexapp.agents.*` plugin reference, with its `/function/<name>` when present. |
| `poc_client` | `X-Plex-Target-Client-Identifier` (header or query) starts with `poc_`. |

`callback_ip` is the address embedded in a `sslip.io`/`nip.io` name, read from the name alone. Query and header text is scanned up to 16 KiB, fields are capped at 256 B, and `truncated` is set when either applies. The Spicy `http` handler does not set `plex2shell`.

#### Local file include (LFI)

`protocols/tcp/lfi.go`. A GET whose **query** or **path** looks like a traversal to a known file (`passwd`, `hosts`, `win.ini`, `amportal.conf`) gets `200` `text/plain` with a canned body from `resources/lfi/`. Examples: `?file=../../etc/passwd`, `/..%2F..%2Fetc%2Fpasswd`. Citrix `/vpn/../vpns/` staging still wins when it matches first. Unknown basenames keep the generic empty `200`.

> **Change (2026-10-17):** before this date, only the query string was inspected, so path-only traversals (e.g. Ochi event 02d72548-cfa1-429d-9959-c76e7564ce67) got an empty body.

## `http` (Spicy)

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `query`, `parameters`, `status`, `browser`, `binary`, `args`, `truncated`, `citrix`, `payload`

Keep-alive HTTP parsed with Spicy. `command`, `query`, `parameters`, and `status` mean the same as in the [Go handler](#frame-fields). Differences from the Go handler:

- **One event per connection.** There is no cross-connection `session` cookie grouping, so no `session_id`, `dest_port`, or `src_port` frame fields.
- **No header-derived fields.** `host` (the sensor address), `user_agent`, and other request headers are not decoded; `payload` still holds the raw wire request/response.
- **Selenium Grid 4:** same paths, replies, and `browser`/`binary`/`args` fields as the [Go handler](#selenium-grid-4).
- **Citrix CVE-2019-19781:** same replies and `citrix` frames as the [Go handler](#citrix-adc--netscaler-gateway-cve-2019-19781), except `nsc_user` is never set (headers are not exposed).
- **LFI:** same path- and query-based canned replies as the [Go handler](#local-file-include-lfi).
- **Proxmox VE:** not emulated.
