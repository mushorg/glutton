# `stun` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `transaction_id`, `attributes`, `software`, `payload`, `truncated`

STUN (RFC 5389/8489) on udp/3478, and on any port through a strict catch-all peek (top two bits zero, magic cookie `2112a442`, 4-byte aligned length equal to the rest of the datagram). `command` is `<method>-<class>`: `binding-request`, `binding-indication`, `allocate-request` (TURN), `refresh-request`, and so on; unknown methods are `method_0x…`. `transaction_id` is the 12-byte transaction ID in hex, `attributes` lists the attribute names in order (`software`, `fingerprint`, `username`, `xor-mapped-address`, …; unknown ones are `attr_0x…`), and `software` holds the SOFTWARE attribute text. A message that does not parse is recorded with `command` `unknown` and no reply.

Replies go through `ReplyUDP`:

- Binding Request: `write` frame `command` `binding-success`, `status` `success`, a 76-byte (IPv4) or 100-byte (IPv6) Binding Success Response with the same transaction ID and coturn's attribute order: XOR-MAPPED-ADDRESS and MAPPED-ADDRESS (both the source address and port), SOFTWARE `Coturn-4.6.2 'Gorst'` and FINGERPRINT (CRC-32 XOR `0x5354554e`). The `write` frame's `attributes` and `software` describe the reply. RESPONSE-ORIGIN and OTHER-ADDRESS are not sent: they would carry the sensor's local address. Sensors before this change replied with only XOR-MAPPED-ADDRESS (32 bytes).
- Everything else (TURN allocate, indications, responses) is recorded only. No TURN relay or authentication is emulated.

Probes seen: 20-byte Binding Request `0001 0000 2112a442` with transaction ID `307755703271327871716a6a` from 207.90.244[.]25 (Shodan, SHODAN-01) to udp/8088 (2026-11-06, 2026-11-08).
