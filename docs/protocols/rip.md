# `rip` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `version`, `whole_table`, `entries`, `auth_type`, `password`, `key_id`, `sequence`, `status`, `payload`, `truncated`

RIPv1 (RFC 1058) and RIPv2 (RFC 2453) on udp/520. `command` is `request`, `response`, `traceon`, `traceoff`, `poll` or `unknown` (header shorter than 4 bytes). `version` is the header version byte. `entries` lists the route entries as `{afi, route_tag, address, mask, next_hop, metric}`; `route_tag`, `mask` and `next_hop` are only set for RIPv2. `whole_table` is set on a request with exactly one entry of AFI 0 and metric 16, which asks for the entire routing table (the classic internet-wide RIP probe). A RIPv2 authentication entry sets `auth_type` (`simple`, `keyed`, or the hex type): `password` is the plaintext password with trailing NULs removed, and `key_id`/`sequence` come from a keyed-digest entry. Only the raw `payload` keeps the digest.

A valid request gets a `write` frame (`command` `response`, `status` `response`) from a router that knows one directly connected network. That network is a stable per-sensor `192.168.x.0/24` at metric 1. A whole-table request gets that one route. A specific request gets each entry back, with metric 1 if the entry is the sensor's network and 16 otherwise. The reply never has more route entries than the request, so it is never larger than the request. Responses from the client (route injection), other commands, malformed datagrams (wrong version, partial entry, no entries, more than 25 entries) and datagrams over 1024 bytes (`truncated`) are recorded only. Replies go to the datagram source and count toward `udp_reply_limit`.

Generic `udp` reroutes datagrams on any port that are a request or response, version 1 or 2, have a zero header word, a length of 4 + 20·n (1 ≤ n ≤ 25), entries with AFI 0/2 (or 0xffff in RIPv2) and metric 1–16, and zero must-be-zero fields in RIPv1.
