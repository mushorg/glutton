# `whois` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `truncated`

WHOIS (tcp/43, RFC 3912). One query line per session: the `read` frame sets `command` to the query (CRLF trimmed; capped at 512 bytes, `truncated` when exceeded) and the `write` frame (`status` `no-match`) is a generic registry-style "no entries found" line. A client that sends nothing yields an empty array.
