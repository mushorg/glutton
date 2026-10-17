# `snmp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `version`, `community`, `request_id`, `non_repeaters`, `max_repetitions`, `oids`, `status`, `payload`, `truncated`

SNMPv1/v2c (RFC 3416) on udp/161. The `read` frame has `version` (`v1`, `v2c`, `v3`), `community` (plaintext, as sent), `command` (the PDU: `GetRequest`, `GetNextRequest`, `GetBulkRequest`, `SetRequest`, `InformRequest`, `SNMPv2-Trap`, ...), `request_id` (the signed INTEGER from the wire), `oids` (dotted, up to 64) and, for GetBulk, `non_repeaters` and `max_repetitions`. A datagram that does not parse is recorded with `command` `unknown` and no reply. SNMPv3 is recognized (`version` `v3`, `command` `unknown`) but not decoded or answered.

The honeypot is a read-only embedded Linux router. The persona (kernel, build date, architecture, host name `gw-xxxx`, boot time) is derived per process, and `sysUpTime` advances. It answers community `public` only, for the system group `1.3.6.1.2.1.1` (`sysDescr`, `sysObjectID`, `sysUpTime`, `sysContact`, `sysName`, `sysLocation`):

- GET: values, `noSuchObject` for unknown OIDs (v2c) or `noSuchName` (v1, `status` `no_such_name`).
- GETNEXT / GETBULK: walk the system group and end with `endOfMibView`. Repetitions are capped at 64.
- SET: `noAccess` (v2c, `status` `no_access`) or `noSuchName` (v1). Nothing is ever written.
- Any other community, SNMPv3, GetBulk over v1 and non-request PDUs get no reply, as a real agent drops them. They are still recorded.

Replies are never larger than the request (reflection abuse resistance). A GetBulk reply drops trailing bindings until it fits; a Get/GetNext/Set reply that does not fit becomes a `tooBig` error (`status` `too_big`, empty bindings), and if even that does not fit nothing is sent. Most minimal probes therefore see `tooBig`. The `write` frame has `command` `GetResponse` and `status` `ok`, `too_big`, `no_such_name` or `no_access`. Replies go to the datagram source and count toward `udp_reply_limit`.

Probes seen: a v2c GetBulk of `1.3.6.1` with `max-repetitions` 2000 and community `public` (Ochi event 7046da12-95f6-463e-8b55-8df479078229), the shape of an SNMP discovery and amplification check (a guess).

Generic `udp` reroutes well-formed SNMP on any port: an outer SEQUENCE spanning the datagram, version 0, 1 or 3, and for v1/v2c a community followed by a PDU tag 0xA0-0xA7 (v3: the msgGlobalData SEQUENCE). `udp dst port 161` maps to `snmp` before the catch-all.
