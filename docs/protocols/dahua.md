# `dahua` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `username`, `password`, `nonce`, `status`, `payload`, `truncated`

Dahua DVR/NVR private protocol (tcp/37777). Frames are a 32-byte header plus a body; the layout is inferred from captured logins, not from a spec. `command` is `login` (header byte `0xa0`) or `cmd-0xNN` for other command bytes. `username` and `password` are recorded in plaintext; the full values come from the `user&&pass` body, since the header fields hold only 8 bytes. `nonce` is the client `Random:` value. Logins get a 32-byte rejection (`0xb0` response, status byte `0x01` at offset 8, unverified against a real device) with write `status` `login-denied`; other commands get no reply. Bodies over 64 KiB are stored up to the cap with `truncated` and end the session (`read_error`).
