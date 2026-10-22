# `rcon` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `request_id`, `size`, `size_mismatch`, `password`, `body`, `status`, `payload`, `truncated`

Valve Source RCON (srcds remote console, tcp/27015), the protocol game server admins and tools such as `rcon-cli` use to run console commands. Every packet is a little-endian int32 size (the bytes after it), an int32 request id and an int32 type, then a NUL-terminated ASCII body and a trailing empty string. The layout follows the Valve Developer Community "Source RCON Protocol" page.

Each packet is a `read` frame with `command` (`auth` for SERVERDATA_AUTH, `exec` for SERVERDATA_EXECCOMMAND, `response` for SERVERDATA_RESPONSE_VALUE, or `unknown`), `request_id`, and the declared `size`. The body of an `auth` packet is the `password` guess, recorded in plaintext; any other body goes in `body` (the console command for `exec`). Bodies are framed by their NUL terminators rather than the size field, because some scanners send a wrong size (Shodan's auth probe declares 10 bytes and sends 14); `size_mismatch` is set when the two disagree. A body longer than 4086 bytes is cut at that cap (`truncated`) and the session ends.

The honeypot answers like a server with a different `rcon_password`. Each `auth` gets one `write` frame with `status` `auth-failed` and `request_id` -1: an empty RESPONSE_VALUE that echoes the request id, followed by an AUTH_RESPONSE with id -1. The connection stays open for further guesses, up to 16 packets (`endReason` `max_frames`). An `exec` is recorded and the connection closes with no reply, since nothing is ever authenticated. `response` and `unknown` packets get no reply. A header whose size field is outside 10–4096 is recorded as a `read` frame without `command`, and the connection closes. A short header is recorded as received.
