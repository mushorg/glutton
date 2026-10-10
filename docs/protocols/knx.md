# `knx` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `service_type`, `hpai_ip`, `hpai_port`, `status`, `payload`, `truncated`

KNXnet/IP (udp/3671). `command` is `SEARCH_REQUEST`, `DESCRIPTION_REQUEST`, `CONNECT_REQUEST`, `CONNECTIONSTATE_REQUEST`, `DISCONNECT_REQUEST` or `UNKNOWN` (truncated header, bad magic, length not equal to the datagram length, malformed HPAI); `service_type` is the hex code (e.g. `0x0203`) when the header was readable. `hpai_ip`/`hpai_port` are the endpoint the client claims, which is often its real address behind NAT; it is recorded, never contacted or replied to. `DESCRIPTION_REQUEST` gets a `write` `DESCRIPTION_RESPONSE` and `SEARCH_REQUEST` a `SEARCH_RESPONSE` (`status`) from a stable per-sensor TP1 gateway identity (derived serial and MAC); `CONNECT_REQUEST` gets a `CONNECT_RESPONSE` with `E_NO_MORE_CONNECTIONS`. Other services are recorded only. Replies always go to the datagram source and are limited to one per source IP per minute (the reply is ~5x the probe). Datagrams over 1024 bytes are capped with `truncated`.
