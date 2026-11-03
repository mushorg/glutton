# `ntp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `version`, `mode`, `implementation`, `request_code`, `opcode`, `stratum`, `payload`, `truncated`

NTP on udp/123 (also via a strict catch-all peek on any port). `command` is the leaf operation: `client`, `server`, `symmetric_active`, `symmetric_passive`, `broadcast` (modes 1-5), the mode 6 control opcode (`readstat`, `readvar`, `read_mru`, ...) or the mode 7 private request name (`mon_getlist`, `mon_getlist_1` (monlist), `peer_list`, `sys_info`, `get_restrict`, ...). Mode 7 frames also carry `implementation` (3 = xntpd) and `request_code`; mode 6 frames carry `opcode`. A datagram that does not parse is recorded with `command` `unknown` and no reply.

Replies go through `ReplyUDP` and are never larger than the request:

- mode 3 client packet (48 bytes): `write` frame `status` `server`, a stratum 2 mode 4 packet with the client's transmit timestamp echoed as origin;
- mode 6 control request: 12-byte error response (CERR_PERMISSION), `status` `error`;
- mode 7 private request (monlist and friends): 8-byte error response (INFO_ERR_REQ), `status` `error`. No monlist table is emulated, so the sensor is not an amplifier;
- other modes and responses are recorded only.

Probes seen: 192-byte `17 00 03 2a` + zeros from 174.138.53[.]53, i.e. monlist (`REQ_MON_GETLIST_1`) (Ochi event 55bbf2fb-5298-4c11-9d1a-0ff70f5a0e80).

Generic `udp` reroutes (any port): 48-byte VN 3/4 client packets, mode 6 requests with a known opcode, and mode 7 requests with implementation 0/2/3 and a known request code.
