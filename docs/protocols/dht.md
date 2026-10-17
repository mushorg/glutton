# `dht` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `node_id`, `target`, `info_hash`, `want`, `transaction`, `port`, `payload`, `truncated`

BitTorrent Mainline DHT (BEP 5) on udp/6881 (also via catch-all peek on any port). Distinct from the TCP `bittorrent` peer-handshake handler. The `read` frame has `command` `ping`, `find_node`, `get_peers` or `announce_peer`; `node_id` / `target` / `info_hash` are hex of the 20-byte fields; `want` is `n4`, `n6` or `n4,n6` when present; `transaction` is hex of `t`; `port` is set on `announce_peer`. A datagram that does not parse is recorded with `command` `unknown` and no reply.

Every valid query gets one `write` frame with the same `command`, `status` `response`, the sensor's stable node id, and a bencoded reply that echoes `t`. `find_node` / `get_peers` advertise the listen address in compact `nodes` / `nodes6` when `want` asks for them; `get_peers` also includes a short `token`. The reply is never larger than the request (optional fields are dropped first), so the sensor is not a DHT amplifier. No swarm is joined, no peers are dialed, and announce tokens are not validated against real torrents. Replies go to the datagram source and count toward `udp_reply_limit`.

Probes seen: Shodan `find_node` with `want` `n4n6` and a fixed-looking ASCII node id (Ochi event ead994ab-d411-4a68-b117-8f827a383583, `mechanicus.census.shodan.io`).

Generic `udp` reroutes datagrams on any port that are a bencoded query (`1:y1:q`) for `ping` / `find_node` / `get_peers` / `announce_peer`.
