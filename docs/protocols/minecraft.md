# `minecraft` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `protocol_version`, `port`, `next_state`, `username`, `truncated`, `payload`

Minecraft Java. `command` is `handshake` (`path` is the server address the client typed), `status_request`, `ping`, `login_start` (`username`), `malformed` (partial or oversize frame, `truncated`) or `unknown`. Writes set `status` `status_response`, `pong` or `disconnect`. The status JSON echoes a positive client protocol version, otherwise 769. No encryption or real login.
