# `http` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

Glutton has two `http` handlers: the Go handler (default) and a Spicy-based one. Both emit per-direction frames and emulate the same applications (Selenium Grid, Citrix); they differ in session grouping and which header-derived fields they decode. See [Spicy differences](#http-spicy).

## `http` (Go)

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `query`, `parameters`, `host`, `username`, `user_agent`, `status`, `browser`, `binary`, `args`, `truncated`, `citrix`, `session_id`, `dest_port`, `src_port`, `payload`

### Frame fields

| Field | Set on | Meaning |
| --- | --- | --- |
| `command` | reads | HTTP method. |
| `query` | reads | Raw query string. |
| `parameters` | reads | Parsed query map. |
| `dest_port`, `src_port` | reads | Ports of the connection the frame arrived on (see [Sessions](#sessions)). |
| `status` | writes | Response status, e.g. `200`. |
| `username`, `browser`, `binary`, `args`, `citrix`, `truncated` | reads | Application-specific; see [Emulated applications](#emulated-applications). |

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

Ticket reads set `username` from the form `username` field, with `@realm` appended when `realm` is sent separately. The password is never decoded.

The default rule terminates TLS on tcp/8006 (`tls: auto`) with a node certificate signed by a per-sensor `PVE Cluster Manager CA`, so the event carries a `tls` object.

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

## `http` (Spicy)

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `query`, `parameters`, `status`, `browser`, `binary`, `args`, `truncated`, `citrix`, `payload`

Keep-alive HTTP parsed with Spicy. `command`, `query`, `parameters`, and `status` mean the same as in the [Go handler](#frame-fields). Differences from the Go handler:

- **One event per connection.** There is no cross-connection `session` cookie grouping, so no `session_id`, `dest_port`, or `src_port` frame fields.
- **No header-derived fields.** `host` (the sensor address), `user_agent`, and other request headers are not decoded; `payload` still holds the raw wire request/response.
- **Selenium Grid 4:** same paths, replies, and `browser`/`binary`/`args` fields as the [Go handler](#selenium-grid-4).
- **Citrix CVE-2019-19781:** same replies and `citrix` frames as the [Go handler](#citrix-adc--netscaler-gateway-cve-2019-19781), except `nsc_user` is never set (headers are not exposed).
- **Proxmox VE:** not emulated.
