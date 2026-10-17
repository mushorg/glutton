# `enip` decoded data

Transport: TCP and UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `session_handle`, `sender_context`, `status`, `payload`, `truncated`

EtherNet/IP encapsulation on tcp/44818. `command` is the encapsulation command (`ListIdentity`, `ListServices`, `ListInterfaces`, `RegisterSession`, `UnRegisterSession`, `SendRRData`, `SendUnitData`, `NOP`, `0x....` for unknown) or `malformed` (partial header, `truncated`). `sender_context` is the hex of the 8-byte context the client chose (echoed in replies). Writes set `status` (`success`, `invalid_command`, `invalid_session_handle`, `invalid_length`, `unsupported_protocol_revision`). The ListIdentity write payload records the advertised device address as `1.2.3.4`. Oversize requests (over 4096 data bytes) are `truncated`; capped at 32 requests (`endReason` `max_frames`).

**UDP (udp/44818).** The same frame shape is produced once per datagram. ListIdentity, ListServices and ListInterfaces get the same replies as over TCP (same adapter identity and per-process serial); the ListIdentity write payload again records the advertised address as `1.2.3.4`. Every other command is recorded without a reply, and a datagram shorter than a header is a `malformed`, `truncated` read. Payloads over 1024 bytes are `truncated`. Replies go through `ReplyUDP`, so the `udp_reply_limit` budget applies. The catch-all `udp` handler also reroutes strict list requests on any port to `enip`.
