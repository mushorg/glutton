# `wsdiscovery` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `message_id`, `types`, `scopes`, `address`, `status`, `payload`, `truncated`

WS-Discovery SOAP-over-UDP (udp/3702). `command` is the last segment of `wsa:Action` (`Probe`, `Resolve`, `Hello`, `Bye`) or `UNKNOWN` if unparseable. A `Probe` for `wsdp:Device` (or with no types) gets a `write` `ProbeMatches` (`status` `ProbeMatches`) from a stable per-sensor device identity; a `Resolve` for that identity gets `ResolveMatches`. Typed probes for other services (e.g. ONVIF) and other actions are recorded only. Replies are limited to one per source IP per minute and to 4x the request size. Datagrams over 4096 bytes are capped with `truncated`.
