# `a2s` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `request_type`, `query`, `challenge` (hex of wire bytes), `status`, `payload`, `truncated`

Valve Source Engine queries (udp/27015). `command` is `A2S_INFO`, `A2S_PLAYER`, `A2S_RULES`, `A2S_SERVERQUERY_GETCHALLENGE`, `A2A_PING` or `UNKNOWN`; `query` is the A2S_INFO string (`Source Engine Query`). A2S_INFO without a challenge (including scanners that omit the string's NUL terminator), and PLAYER/RULES with challenge `ffffffff`, get a 9-byte `S2C_CHALLENGE` write (`status` `S2C_CHALLENGE`, random `challenge`). Info/player/rules data is never sent and no reply is larger than the request, so the sensor is not an amplifier. Datagrams over 1024 bytes are capped with `truncated`.
