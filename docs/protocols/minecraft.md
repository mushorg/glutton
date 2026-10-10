# `minecraft` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `protocol_version`, `port`, `next_state`, `username`, `truncated`, `payload`

Minecraft Java. `command` is `handshake` (`path` is the server address the client typed), `status_request`, `ping`, `login_start` (`username`), `malformed` (partial or oversize frame, `truncated`) or `unknown`. Writes set `status` `status_response`, `pong` or `disconnect`. The status JSON echoes a positive client protocol version, otherwise 769. No encryption or real login.

The rule routes tcp/25565 here. On any other port the `tcp` catch-all peeks the first segment and reroutes a complete Handshake (length prefix 6–266, packet ID `0x00`, address of 255 bytes or less, next state 1–3, fields ending at the declared length) to this handler, so server-list scanners on high ports (e.g. matscan) show up as `minecraft`.
