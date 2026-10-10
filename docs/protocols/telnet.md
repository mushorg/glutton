# `telnet` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `message`, `payload_hash`

Login reads set `command` `username`/`password`; shell reads use the first token. Successful Mirai `sh` writes `$ ` (prompt, no CRLF) instead of the usual `> `. `wget`/`curl` lines set `path` to the http(s) URL and `payload_hash` when the sample fetch succeeds. IAC negotiation is a separate `read` frame with no command. If the first client bytes are binary (not IAC or text), the handler skips the login flow and records one `read` frame with `command` `tls_client_hello` (`0x16 0x03` prefix) or `binary`; no `telnet login` log. The rule uses `tls: auto`, so real TLS hellos are normally terminated before the handler. Process log: Info `telnet login` with `src_ip`/`src_port`/`dest_port`/`username`/`password`; shell lines at Debug.
