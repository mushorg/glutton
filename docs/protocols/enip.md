# `enip` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `session_handle`, `sender_context`, `status`, `payload`, `truncated`

EtherNet/IP encapsulation on tcp/44818. `command` is the encapsulation command (`ListIdentity`, `ListServices`, `ListInterfaces`, `RegisterSession`, `UnRegisterSession`, `SendRRData`, `SendUnitData`, `NOP`, `0x....` for unknown) or `malformed` (partial header, `truncated`). `sender_context` is the hex of the 8-byte context the client chose (echoed in replies). Writes set `status` (`success`, `invalid_command`, `invalid_session_handle`, `invalid_length`, `unsupported_protocol_revision`). The ListIdentity write payload records the advertised device address as `1.2.3.4`. Oversize requests (over 4096 data bytes) are `truncated`; capped at 32 requests (`endReason` `max_frames`).
