# `steam` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `client_id`, `msg_type`, `sequence_num`, `payload`, `truncated`

Steam In-Home Streaming / Remote Play discovery (udp/27036). The datagram is the magic `ff ff ff ff 21 4c 5f a0`, a little-endian u32 header length, a protobuf `CMsgRemoteClientBroadcastHeader` (`client_id`, `msg_type`), a little-endian u32 body length and the protobuf body. `command` is the `msg_type` name (`discovery`, `status`, `offline`, `device_authorization_request`, …) or `UNKNOWN` when the header could not be decoded. `client_id` is the sender's 64-bit ID in decimal (a scanner picks a random one). `msg_type` is omitted for discovery (0); read `command`. `sequence_num` is set on discovery only.

The classic probe is Censys sending a 28-byte discovery with `sequence_num` 0 (Ochi event 2aa6e947-f427-4454-9776-3f34171ac06f). The handler is parse-only: a real Status reply carries version, hostname, OS and a timestamp and is larger than the probe, so the sensor sends nothing and cannot be used as an amplifier. Datagrams over 1024 bytes are capped with `truncated`. The generic `udp` handler reroutes any datagram starting with the magic to `steam`, and `udp dst port 27036` maps to it before the catch-all.
