# `tftp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `mode`, `options`, `status`, `payload`, `truncated`

TFTP (RFC 1350, options per RFC 2347) on udp/69. The `read` frame has `command` `RRQ` or `WRQ`, `path` (the requested filename, plaintext and capped at 255 bytes), `mode` (`netascii`, `octet` or `mail`, lowercased) and `options` (`{name, value}` pairs such as `blksize`, `tsize`). A request that does not parse is recorded with `command` `unknown` and no reply.

Every valid request gets one `write` frame with `command` `ERROR`: `status` `file_not_found` (ERROR 1) for an RRQ and `access_violation` (ERROR 2) for a WRQ. The error message is trimmed only when needed so the reply is never larger than the request (the `polycom430` probe gets the full `File not found`, 19 bytes for a 19-byte request). No file is served or accepted, and the handler never opens a data connection (the transfer would use a new source port). Replies go to the datagram source and count toward `udp_reply_limit`.

Probes seen: `polycom430` in `octet` mode (Ochi event 59795bc9-f579-42b8-890d-8dab9b753ff3), a sweep for exposed VoIP phone provisioning servers (a guess). Real Polycom phones ask for `000000000000.cfg` or `<MAC>.cfg`.

Generic `udp` reroutes datagrams on any port that are a well-formed RRQ/WRQ: opcode 1 or 2, a non-empty NUL-terminated filename, a valid mode, and only complete option pairs after it.
