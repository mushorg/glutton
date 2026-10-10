# `raknet` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of read frames: `direction`, `command`, `packet_id`, `packet_name`, `protocol`, `magic_ok`, `mtu`, `payload`, `truncated`

`command` copies `packet_name`. Parse-only; no Open Connection Reply or Unconnected Pong. `0x05` OCR1 sets `protocol` (byte after magic) and `mtu` (datagram length). Generic UDP peeks the same magic and reroutes here.
