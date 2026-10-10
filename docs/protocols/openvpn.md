# `openvpn` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of read frames: `direction`, `command`, `opcode`, `opcode_name`, `key_id`, `session_id` (hex), `ack_count`, `packet_id`, `malformed`, `payload`, `truncated`; write frames add `status`

`command` copies `opcode_name`. `ack_count`/`packet_id` are parsed from client hard resets (opcodes 1 and 7); `malformed` marks a reset too short to hold them (e.g. the 13-byte scanner probe). Replies only when `openvpn.reply` is true, then a `write` frame `P_CONTROL_HARD_RESET_SERVER_V2` follows a well-formed reset.
