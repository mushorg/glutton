# `minecraft` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `protocol_version`, `port`, `next_state`, `username`, `truncated`, `payload`

Minecraft Java. `command` is `handshake` (`path` is the server address the client typed), `status_request`, `ping`, `login_start` (`username`), `malformed` (partial or oversize frame, `truncated`) or `unknown`. Writes set `status` `status_response`, `pong`, or the login Disconnect reason: `incompatible` / `outdated_client` (login Handshake protocol is not 769; below 754 is `outdated_client`), `transfers_disabled` (next state 3), or `not_whitelisted` (Login Start with protocol 769).

Replies mimic a vanilla 1.21.4 dedicated server in offline mode with a whitelist: the status JSON is `{"description":"A Minecraft Server","players":{"max":20,"online":0},"version":{"name":"1.21.4","protocol":769}}` whatever protocol the client sends, and disconnects carry translatable components (`{"translate":"multiplayer.disconnect.…"}`). Version and transfer rejections are sent right after the Handshake, as vanilla does, so they come before any Login Start. The handler then waits up to 500 ms for a Login Start already in flight and records it (`username`) without answering. A second Status Request closes the session. No encryption or real login.

The rule routes tcp/25565 here. On any other port the `tcp` catch-all peeks the first segment and reroutes a complete Handshake (length prefix 6–266, packet ID `0x00`, address of 255 bytes or less, next state 1–3, fields ending at the declared length) to this handler, so server-list scanners on high ports (e.g. matscan) show up as `minecraft`.
