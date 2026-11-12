# `http` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

Glutton has two `http` handlers: the Go handler (default) and a Spicy-based one. Both emit per-direction frames and emulate the same applications (Selenium Grid, Citrix); they differ in session grouping and which header-derived fields they decode. See [Spicy differences](#http-spicy).

## `http` (Go)

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `query`, `parameters`, `host`, `username`, `password`, `user_agent`, `ja4h`, `status`, `browser`, `binary`, `args`, `truncated`, `citrix`, `docker`, `elasticsearch`, `log4shell`, `php2shell`, `phpinfo`, `plex2shell`, `session_id`, `dest_port`, `src_port`, `payload`, `payload_hash` (Docker create/exec bodies), and on [CONNECT tunnel](#connect-proxy-tunnels) frames `payload_hash`, `error`, `requests`, `distinct_requests`, `request_line`, `http`, plus TLS ClientHello fingerprint fields (`sni`, `ja4`, …)

### Frame fields

| Field | Set on | Meaning |
| --- | --- | --- |
| `command` | reads | HTTP method; `tunnel` or `tls-clienthello` for bytes sent through a granted `CONNECT`. |
| `path` | reads | URL path; the `CONNECT` target (`host:port`) on `CONNECT` and tunnel reads. |
| `query` | reads | Raw query string. |
| `parameters` | reads | Parsed query map. |
| `ja4h` | reads | [FoxIO JA4H](https://github.com/FoxIO-LLC/ja4) client fingerprint `a_b_c_d`, computed from the raw request (method, version, cookie/referer flags, header count and language; hashes of header order, sorted cookie names and cookie values). Empty when the request line did not parse. |
| `dest_port`, `src_port` | reads | Ports of the connection the frame arrived on (see [Sessions](#sessions)). |
| `status` | writes | Response status, e.g. `200`. |
| `username`, `password` | reads | `Authorization: Basic` credentials, otherwise `Proxy-Authorization: Basic` (any method, including `CONNECT`), or the Proxmox VE ticket login form (see [Emulated applications](#emulated-applications)). Recorded in plaintext. |
| `payload_hash`, `truncated`, `error`, `requests`, `distinct_requests`, `request_line`, `http`, `sni`, `ja4`, … | tunnel frames | See [CONNECT proxy tunnels](#connect-proxy-tunnels). |
| `browser`, `binary`, `args`, `citrix`, `docker`, `elasticsearch`, `log4shell`, `php2shell`, `phpinfo`, `plex2shell`, `truncated` | reads | Application-specific; see [Emulated applications](#emulated-applications). |

### Sessions

The handler speaks keep-alive HTTP and groups frames across TCP connections into one produced event:

- Every response sets a `session` cookie. Frames that share that cookie (per source host) are grouped into one event, produced when the session idles out (`conn_timeout`).
- Requests without the cookie (most scanners) join the source IP's latest live session, across connections and destination ports.
- Because one event can span several connections, the top-level `dstPort`/`srcPort` are those of the first connection; each read frame carries its own `dest_port`/`src_port`.
- A session holds at most 500 frames, 8 MiB of payload, or one hour. At the limit the next frame, even on the same keep-alive connection, starts a new event under the same `session_id`; the full one is produced once its last connection ends.
- At most 1024 sessions are tracked at once. When full, the session idle the longest is produced early with `endReason` `evicted`; if every session has an open connection, the new connection produces its own event when it closes.
- The idle session table is shared with [`mcp`](mcp.md).
- The request line plus headers may be at most 64 KiB (bodies at most 1 MiB). A larger header block is recorded up to the cap as an unparsed read and ends the connection with `endReason` `read_error`.
- A complete request that `net/http` rejects (for example a `CONNECT` target with a doubled port, `host:2096:2096`) is answered with `HTTP/1.1 400 Bad Request` and `Connection: close`, and the connection ends with `endReason` `read_error`. The read frame keeps the raw `payload` plus whatever could be salvaged: `command` (when the first token looks like a method), `path` (the raw request target), `host`, `user_agent`, and Basic or Proxy-Authorization `username`/`password`. `ja4h` is empty. Before 2026-11-12 such requests got no reply and the frame held only `direction` and `payload`.

### CONNECT proxy tunnels

A `CONNECT host:port` request is answered like an open proxy: `HTTP/1.1 200 Connection established` with no headers (no `session` cookie, no `Content-Length`). The handler then stops parsing HTTP on that connection and captures what the client sends through the tunnel, using the same code as [`socks`](socks.md) (`protocols/tcp/tunnel.go`). Nothing is dialed, resolved or forwarded.

- The first tunnel bytes (up to `max_tcp_payload`) become a read frame with `command` `tunnel`, `path` the CONNECT target, `payload_hash` (the bytes are stored with `helpers.Store` unless `storage.tunnel_payloads` is `false`), and `truncated` when the cap applied.
- A plaintext HTTP request in the tunnel gets the canned open-proxy judge reply (`{"ip":"198.51.100.10",…}`). A request for a crawler asset path gets the `404` instead (see [Unknown paths](#unknown-paths)). The tunnel frame then carries `requests`/`distinct_requests`/`request_line`/`user_agent` and an `http` array with the request and reply frames.
- A TLS ClientHello is recorded as `command` `tls-clienthello` with its fingerprint fields (it is not stored on disk), answered with a self-signed certificate for the SNI (or CONNECT host) and a `write` with `status` `tls-handshake` (`error` set if it could not be sent). The decrypted first message is the `tunnel` read. The TLS details stay on the frames; the event's top-level `tls` object is not set, because the session can span other connections.
- Opaque data (for example a connect-back checker's random token) gets no reply, and the connection closes with `endReason` `handler_close`.

> **Change (2026-10-24):** before this date `CONNECT` got the generic `200 OK` with `Content-Length: 0`. The tunnel bytes were then parsed as HTTP, so a non-HTTP token sat until the connection timeout and was stored as an untagged read with `endReason` `read_error` (Ochi event 137b2e1d-350c-4e23-bbb6-54a7f0ce35ef). `Proxy-Authorization` credentials were not recorded.

### Unknown paths

A request that no emulated application, POST handler or LFI reply answers gets `200` with an empty body (the judge reply inside a proxy tunnel). The exception is crawler and browser asset paths that a bare server would not have. Those get `404 Not Found` with a small `text/html` body (headers only for `HEAD`), so not every path returns the same reply:

- `/favicon.ico`, `/apple-touch-icon*.png`
- `/sitemap.xml`, `/sitemap_index.xml`
- `/ads.txt`, `/app-ads.txt`, `/humans.txt`
- `/crossdomain.xml`, `/clientaccesspolicy.xml`, `/browserconfig.xml`
- `/site.webmanifest`, `/manifest.json`, `/apple-app-site-association`
- anything under `/.well-known/`

Matching ignores case. `/robots.txt` keeps the empty `200`.

> **Change (2026-11-08):** before this date these paths got the empty `200`, or the judge JSON inside a tunnel. One capture showed seven tunnelled requests across two hosts and two paths (`/`, `/sitemap_index.xml`) that all got the identical 137-byte judge reply.

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

#### cPanel & WHM (cpsrvd)

Package: `protocols/tcp/cpanel`. Every path on the cpsrvd ports is answered as an unauthenticated cpsrvd (`Server: cpsrvd`): cPanel on 2082/2083, WHM on 2086/2087, Webmail on 2095/2096. The default rule uses `tls: auto` on all six, so the TLS ports keep the shared sensor certificate.

| Request | Response |
| --- | --- |
| `GET /`, `GET /login/` | `200` login page (`<title>cPanel Login</title>`, `WHM Login` or `Webmail Login`; form `login_form` posting `user`/`pass` to `/login/`) |
| `POST /login/?login_only=1` | `401 Access Denied`, JSON `{"status":0,...,"message":"invalid_login",...}` |
| `POST /login/` | `401 Access Denied`, login page with "The login is invalid." |
| `/json-api/`, `/execute/`, `/xml-api/`, `/scripts*`, `/frontend/`, `/cpsess*`, `/3rdparty/`, `/webmail/`, `/logout` | `401 Access Denied`, login page |
| Anything else | `404 Not Found` |

Reads set `username`/`password` from the login form (`user`, `pass`) or from an API token header (`Authorization: whm root:<token>` or `cpanel <user>:<token>`; the token goes in `password`), capped at 256 bytes. HTTP Basic is decoded as on every port. No login succeeds and no API call is served, so authentication-bypass probes (e.g. CVE-2026-41940) see a patched host.

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

#### phpinfo() page

Package: `protocols/tcp/phpinfo`. Exposure scanners (Censys, nuclei `phpinfo-files`) request well-known test scripts and record the PHP version and configuration. A matching request sets `phpinfo` to `{page}` (the script name, lowercased) and gets a `200` `text/html` phpinfo() page of a Debian 11 host: PHP 7.4.33, `Server: Apache/2.4.62 (Debian)`, Apache 2.0 Handler, Debian default `php.ini`. Hostname, kernel build and the systemd invocation ID are random per sensor. Request headers, `$_SERVER` values (client address and port, `Host`, URI, `HTTPS` when the sensor terminated TLS) and `$_GET` are reflected, HTML-escaped, as the real page does; at most 64 headers and 32 query parameters, each value capped at 1 KiB. The page carries no credentials or application secrets and accepts no uploads. `HEAD` gets the headers only.

| Path | Matches |
| --- | --- |
| `phpinfo.php`, `info.php`, `infophp.php`, `php_info.php`, `php-info.php`, `pinfo.php`, `phpversion.php`, `inf0.php`, `infos.php`, `old_phpinfo.php`, `linusadmin-phpinfo.php`, `phpinfo` | in any directory (`/public/phpinfo.php`, `/_profiler/phpinfo`, `/dashboard/phpinfo.php`) |
| `i.php`, `pi.php`, `p.php`, `php.php`, `php2.php`, `test.php`, `a.php`, `asdf.php`, `time.php`, `temp.php`, `testxx.php` | at the web root only |
| `/?phpinfo=1`, `/index.php?phpinfo=1`, `/l.php?act=phpinfo` | by query |

The Selenium, Proxmox VE, Elasticsearch, Docker, Plex and Citrix personas answer first on their ports and paths. The Spicy `http` handler does not set `phpinfo`.

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

#### Docker Engine API

Package: `protocols/tcp/dockerapi`. Every path on tcp/2375 and tcp/2376 is answered as an unauthenticated Docker Engine 20.10.9 daemon (API 1.41) on a Debian 11 host with no containers or images. The rule uses `tls: auto`, so plain HTTP and HTTPS both reach the persona. Replies carry `Api-Version: 1.41`, `Docker-Experimental: false`, `Ostype: linux` and `Server: Docker/20.10.9 (linux)`, plus the `session` cookie. Routes may carry a `/vX.Y` API version prefix. Nothing is pulled, created or executed: IDs are random and every output stream is empty, so the container chain of a cryptojacking bot runs to the end without doing anything.

| Request | `operation` | Reply |
| --- | --- | --- |
| `GET`/`HEAD /_ping` | `ping` | `200` `OK` (`text/plain`) |
| `GET /version` | `version` | `200` with the `resources/docker_api.json` version object |
| `GET /info` | `info` | `200` host summary (overlay2, cgroup v2, 4 CPUs, 0 containers); `Name` (`srv-<6 hex>`) and the daemon `ID` are random per sensor |
| `GET /containers/json`, `GET /images/json` | `container_list`, `image_list` | `200` `[]` |
| `POST /images/create?fromImage=&tag=` | `image_create` | `200` pull stream: `Pulling from`, a digest derived from the name, `Image is up to date` |
| `POST /containers/create` | `container_create` | `201` `{"Id":"<64 hex>","Warnings":[]}` |
| `POST /containers/<id>/start`, `stop`, `kill`, `restart`, `DELETE /containers/<id>` | `container_start`, … , `container_delete` | `204` |
| `POST /containers/<id>/wait` | `container_wait` | `200` `{"Error":null,"StatusCode":0}` |
| `POST /containers/<id>/attach`, `GET /containers/<id>/logs` | `container_attach`, `container_logs` | `200` empty `application/vnd.docker.raw-stream` |
| `POST /containers/<id>/exec` | `container_exec` | `201` `{"Id":"<64 hex>"}` |
| `POST /exec/<id>/start` | `exec_start` | `200` empty raw stream |
| `GET /exec/<id>/json` | `exec_inspect` | `200` `{"ID":…,"Running":false,"ExitCode":0,"Pid":0}` |
| anything else | `unknown` | `404` `{"message":"page not found"}` |

The persona keeps no state: a created container is not listed by `/containers/json`, and any ID is accepted. Every read on these ports sets `docker` to `{operation, id, image, cmd, entrypoint, env, binds, privileged, user, truncated}`. `id` comes from the path, `image` from the create body or `fromImage[:tag]`, and `cmd`, `entrypoint`, `env`, `binds` (`HostConfig.Binds`, e.g. `/:/host`), `privileged` and `user` from the create or exec JSON body (`Cmd`/`Entrypoint` may be a string or an array). Caps: 32 entries per list, 4 KiB per `cmd`/`entrypoint`/`env` entry, 1 KiB per bind, 256 B for `image`/`id`/`user`; `truncated` is set when one applies. Create and exec bodies of 4 KiB or more are also stored with `helpers.Store` under `payloads/docker/`, and the read frame gets `payload_hash`. The raw `payload` always holds the full request. The Spicy `http` handler answers only `/v1.16/version`.

> **Change (2026-11-08):** before this date tcp/2375 and tcp/2376 reached the catch-all `tcp` handler. On 2376 it completed the TLS handshake and then answered any request with random bytes. Later on 2026-11-08 the persona gained `/info`, image pull and the container create/start/exec chain plus the `docker` frame field; before that, `POST /containers/create` and everything past recon got `404`.

#### Elasticsearch 1.4

Package: `protocols/tcp/elasticsearch`. Every path on tcp/9200 is answered as an unauthenticated Elasticsearch 1.4.2 node: version 1.4.2 is still vulnerable to the dynamic-scripting RCEs scanners probe for (CVE-2014-3120 MVEL, CVE-2015-1427 Groovy). The node is a fresh single-node cluster with no indices, so searches return no hits and scripts never produce output. Scripts are recorded and never evaluated. The endpoint list follows [elasticpot](https://gitlab.com/bontchev/elasticpot); the replies are written from the public ES 1.x REST API. Replies carry only `Content-Type` and `Content-Length`, as ES 1.x does (plus the `session` cookie).

| Request | Response |
| --- | --- |
| `GET`/`HEAD /` | `200` pretty-printed banner: node `name`, `cluster_name`, `version.number` `1.4.2`, tagline |
| `_search`, `_count` (no index, `_all` or a wildcard) | `200`, zero hits (`?source=` bodies are read too) |
| `/<index>/_search`, `GET /<index>`, document `GET`/`DELETE`, `DELETE /<index>` | `404` `IndexMissingException[[<index>] missing]` |
| `DELETE /*`, `DELETE /_all`, `PUT`/`POST /<index>` | `200` `{"acknowledged":true}` |
| `PUT`/`POST /<index>/<type>[/<id>]` | `201` `created:true`, `_version` 1, a random 20-char `_id` when none is given |
| `/_cluster/health` | `200` green, 1 node, 0 shards |
| `/_nodes*` | `200` the node (`inet[/172.31.x.y:9300]`) |
| `/_cat`, `/_cat/{indices,nodes,master,aliases,shards,plugins}` | `200` text (`?v` adds the header row) or `?format=json` |
| `/_stats`, `/_mapping`, `/_settings`, `/_aliases`, `/_alias` | `200` empty |
| Anything else | `400` `No handler found for uri [<path>] and method [<method>]` |

`?pretty` pretty-prints JSON replies the way ES does (`"key" : value`). Every read on tcp/9200 sets `elasticsearch` to `{operation, index, type, id, lang, scripts, truncated}`:

- `operation` is the REST operation: `info`, `search`, `count`, `cat`, `cat_indices`, `cat_nodes`, …, `cluster_health`, `nodes`, `stats`, `mapping`, `settings`, `aliases`, `alias`, `get_index`, `create_index`, `delete_index`, `index_document`, `get_document`, `delete_document`, or `unknown`.
- `index`, `type`, `id` come from the path (percent-decoded, so `/%2A/_alias` has index `*`).
- `scripts` holds every `script` value in a JSON body or `?source=` (a string, or the `script`/`inline`/`source` field of a script object), and `lang` the first `lang` (`groovy`, `mvel`).

Caps: 8 scripts of 4 KiB, 256 B for `index`/`type`/`id`/`lang`, and JSON nesting depth 32; `truncated` is set when any applies. Node `name` and `cluster_name` come from `elasticsearch.node_name` and `elasticsearch.cluster_name` (see [Configuration](../configuration.md)). The Spicy `http` handler does not set `elasticsearch`.

#### Ethereum JSON-RPC

`protocols/tcp/ethereum_rpc.go`. A `POST` whose body is a JSON-RPC request or batch with an `eth_`, `web3_` or `net_` method is answered like a geth node, as `Geth/LVIV/v1.0.0/linux/go1.4.2` (the same string as the `extraData` of the block returned by `eth_getBlockByNumber`). The node answers `eth_blockNumber`, `eth_getBlockByNumber`, `eth_accounts` and `web3_clientVersion`. Every other method gets error `-32601` (`the method <name> does not exist/is not available`). The reply echoes the request `id` (number or string). A single request gets a single object, and a batch gets an array. No extra frame fields; the method is in the read `payload`.

> **Change (2026-11-12):** before this date, only bodies containing `eth_blockNumber` were routed here. Every reply was an array, even for a single request, and unknown methods (including the Shodan `web3_clientVersion` probe on tcp/8545) were silently dropped.

#### Local file include (LFI)

`protocols/tcp/lfi.go`. A GET whose **query** or **path** looks like a traversal to a known file (`passwd`, `hosts`, `win.ini`, `amportal.conf`) gets `200` `text/plain` with a canned body from `resources/lfi/`. Examples: `?file=../../etc/passwd`, `/..%2F..%2Fetc%2Fpasswd`. Citrix `/vpn/../vpns/` staging still wins when it matches first. Unknown basenames keep the generic empty `200`.

> **Change (2026-10-17):** before this date, only the query string was inspected, so path-only traversals (e.g. Ochi event 02d72548-cfa1-429d-9959-c76e7564ce67) got an empty body.

## `http` (Spicy)

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `query`, `parameters`, `status`, `browser`, `binary`, `args`, `truncated`, `citrix`, `payload`

Keep-alive HTTP parsed with Spicy. `command`, `query`, `parameters`, and `status` mean the same as in the [Go handler](#frame-fields). Differences from the Go handler:

- **CONNECT goes to the Go handler.** When the catch-all detects HTTP and the first request is `CONNECT`, the connection is handed to the Go handler, so [CONNECT proxy tunnels](#connect-proxy-tunnels) behave the same with Spicy enabled.
- **Header cap.** The request line plus headers may be at most 64 KiB, as in the Go handler.
- **One event per connection.** There is no cross-connection `session` cookie grouping, so no `session_id`, `dest_port`, or `src_port` frame fields.
- **No header-derived fields.** `host` (the sensor address), `user_agent`, and other request headers are not decoded; `payload` still holds the raw wire request/response.
- **Selenium Grid 4:** same paths, replies, and `browser`/`binary`/`args` fields as the [Go handler](#selenium-grid-4).
- **Citrix CVE-2019-19781:** same replies and `citrix` frames as the [Go handler](#citrix-adc--netscaler-gateway-cve-2019-19781), except `nsc_user` is never set (headers are not exposed).
- **LFI:** same path- and query-based canned replies as the [Go handler](#local-file-include-lfi).
- **Proxmox VE:** not emulated.
- **Elasticsearch:** not emulated.
- **Docker Engine API:** only `/v1.16/version` is answered.
- **Ethereum JSON-RPC:** only bodies containing `eth_blockNumber` are answered, always with a fixed `eth_blockNumber` result and `id` 0.
