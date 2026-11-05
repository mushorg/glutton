# `tuya` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `seq`, `version`, `checksum`, `status`, `payload`, `truncated`

Tuya local LAN protocol (tcp/6668), spoken by Tuya/Smart Life plugs, bulbs and other IoT devices. Frames (protocol 3.1–3.4) are `000055aa | seq | cmd | len` (big-endian, 16 bytes), a body, then a CRC32 and `0000aa55`. `command` is the command name as used by tinytuya (`dp-query` for `0x0a`, `control`, `heartbeat`, `control-new`, `sess-key-neg-start`, ...) or `cmd-0xNN`. `seq` is the client sequence number. `version` is the plaintext `3.x` tag that precedes the encrypted body of most 3.2+ commands (absent for 3.3 DP_QUERY). `checksum` is `crc32-ok` when the trailer matches, otherwise `mismatch` (bad CRC, or a 3.4 HMAC frame). Bodies are AES-encrypted with a per-device key and are never decrypted.

Every frame gets a reply that echoes `seq` and the command: heartbeats get an empty acknowledgement (return code 0, write `status` `heartbeat`). Anything else gets the plaintext `json obj data unvalid` with return code 1, which is what a device sends when the body does not decrypt with its local key (write `status` `data-unvalid`). A frame without the `000055aa` prefix, a length shorter than the footer, or a length over 64 KiB (stored up to the cap with `truncated`) ends the session with `read_error`. After 20 requests the session ends with `max_frames`. Protocol 3.5 (`00006699` prefix) is not parsed and ends at the prefix check.
