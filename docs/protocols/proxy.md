# `proxy_tcp`, `proxy_udp` decoded data

Transport: TCP/UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Per-direction entries: `direction`, `payload`, `payload_hash`, `bytes`, `truncated`

Only when `capture_traffic.enabled` is true. Samples are capped by `max_tcp_payload`; `truncated` is whether more bytes were forwarded than captured. `proxy_udp` emits one event per flow when the flow idles out or closes.
