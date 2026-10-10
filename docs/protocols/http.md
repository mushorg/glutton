# `http` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

## `http` (Go)

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `query`, `parameters`, `host`, `user_agent`, `status`, `browser`, `binary`, `args`, `truncated`, `session_id`, `dest_port`, `src_port`, `payload`

Keep-alive HTTP. `command` is the HTTP method. Reads set `query` (raw) and `parameters` (parsed query map). Writes set `status` (e.g. `200`). Responses set a `session` cookie; frames that share that cookie (per source host) are grouped into one produced event when the session idles out (`conn_timeout`). Requests without the cookie (most scanners) join the source IP's latest live session, across connections and destination ports, so the top-level `dstPort`/`srcPort` are those of the first connection and reads carry their own `dest_port`/`src_port`. A source session stops taking new cookieless connections after 500 frames or one hour. Shares the idle session table with `mcp`. Selenium Grid 4 (`protocols/tcp/selenium`): every path on tcp/4444 and `/wd/hub/*` on any port is answered as an unauthenticated Grid (`/status` ready JSON, `/` → `302 /ui/`, `/graphql` grid fields, other paths `404 unknown command`). `POST /session` reads set `browser`, `binary`, `args` (from `goog:chromeOptions`/`moz:firefoxOptions`/`ms:edgeOptions`, capped at 64 args of 4 KiB and a 1 KiB binary, `truncated` when cut) and are answered `500 session not created` (Chrome "exited normally"), so no session exists.

## `http` (Spicy)

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `query`, `parameters`, `status`, `browser`, `binary`, `args`, `truncated`, `payload`

Keep-alive HTTP parsed with Spicy. `command` is the HTTP method; reads set `query` (raw) and `parameters` (parsed query map); writes set `status`. Host and other request headers are omitted from decoded fields (sensor address); `payload` is the raw wire request/response. One event per connection (no cross-connection session cookie grouping). Selenium Grid 4 (`protocols/tcp/selenium`): every path on tcp/4444 and `/wd/hub/*` on any port is answered as an unauthenticated Grid (`/status` ready JSON, `/` → `302 /ui/`, `/graphql` grid fields, other paths `404 unknown command`). `POST /session` reads set `browser`, `binary`, `args` (from `goog:chromeOptions`/`moz:firefoxOptions`/`ms:edgeOptions`, capped at 64 args of 4 KiB and a 1 KiB binary, `truncated` when cut) and are answered `500 session not created` (Chrome "exited normally"), so no session exists.
