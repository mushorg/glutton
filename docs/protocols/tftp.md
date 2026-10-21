# `tftp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `mode`, `options`, `status`, `payload`, `truncated`

TFTP (RFC 1350, options per RFC 2347) on udp/69. The `read` frame has `command` `RRQ` or `WRQ`, `path` (the requested filename, plaintext and capped at 255 bytes), `mode` (`netascii`, `octet` or `mail`, lowercased) and `options` (`{name, value}` pairs such as `blksize`, `tsize`). A request that does not parse is recorded with `command` `unknown` and no reply.

Every valid request gets one `write` frame. An RRQ that carries a recognised RFC 2347 option gets `command` `OACK`, `status` `oack`, and `options` holding the acknowledged pairs: `tsize` (only when the client sent `0`; answered with a size derived from the filename, so repeat probes agree), `blksize` (8 or more, clamped to 1468) and `timeout` (1-255). Unknown options, repeated options and out-of-range values are left out, as RFC 2347 allows. Every other request gets `command` `ERROR`: `status` `file_not_found` (ERROR 1) for an RRQ and `access_violation` (ERROR 2) for a WRQ.

Amplification guard: no reply is ever larger than the request. An OACK drops trailing options until it fits, and falls back to the ERROR packet when not even one option fits; the ERROR message is trimmed only when needed (the `polycom430` probe gets the full `File not found`, 19 bytes for a 19-byte request). No file is served or accepted, and the handler never opens a data connection (the transfer would use a new source port), so a client that ACKs block 0 is recorded as a separate `unknown` event. Replies go to the datagram source and are charged against a TFTP-only budget first (per source: 4 replies at once, then 1 per second, 256 bytes per second; all sources together: 512 replies at once, 256 per second, 16 KiB per second), then against `udp_reply_limit`. A reply over the TFTP budget is not sent and one `Dropping TFTP replies over the burst budget` warning is logged each time a source (or the global budget) becomes limited; the produced event still contains the `write` frame, as with `udp_reply_limit`. The TFTP budget is fixed in `protocols/udp/tftp.go` (`tftpGuardConfig`), not configurable.

Probes seen: `infrawatch-<32 hex>.probe` in `octet` mode with `tsize=0` and `blksize=16`, a reflection/exposure check (Ochi event a8422eb1-bd48-4720-94e3-f4976a2e5782; the same fleet probes SLP and RADIUS); `polycom430` in `octet` mode (Ochi event 59795bc9-f579-42b8-890d-8dab9b753ff3), a sweep for exposed VoIP phone provisioning servers (a guess). Real Polycom phones ask for `000000000000.cfg` or `<MAC>.cfg`.

Generic `udp` reroutes datagrams on any port that are a well-formed RRQ/WRQ: opcode 1 or 2, a non-empty NUL-terminated filename, a valid mode, and only complete option pairs after it.
