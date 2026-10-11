# `ident` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `server_port`, `client_port`, `status`, `payload`, `truncated`

Identification Protocol (tcp/113, RFC 1413). The client sends `<port-on-server>, <port-on-client>` lines. A line that parses as a port pair gets a `read` frame with `command` `query` and both ports. The honeypot answers each query with `<server>, <client> : ERROR : NO-USER\r\n`, which is what identd says for a connection it does not own. If either port is outside 1–65535, the answer is `ERROR : INVALID-PORT` instead. The `write` frame `status` is `no-user` or `invalid-port`, and only the parsed port numbers are echoed. Up to 4 queries are answered per connection (`endReason` `max_frames` after that). Any other line, or a line over 128 bytes (`truncated`), is recorded as a `read` frame without `command`, and the connection closes with no reply. A client that sends nothing yields an empty array.
