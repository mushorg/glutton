# `socks` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `version`, `host`, `port`, `user`, `methods`, `payload`, `payload_hash`, `truncated`

SOCKS4, SOCKS4a and SOCKS5 (tcp/1080, 4145, and any port via the catch-all peek). Read `command` is `socks4-connect`, `socks4a-connect`, `socks4-bind`, `socks5-greeting` (`methods`), `socks5-auth` (`user`; the password bytes in `payload` are masked with `*`), `socks5-connect`, `socks5-udp-associate`, or `tunnel` (the first bytes the client sent through a granted tunnel, capped at `max_tcp_payload`, with `payload_hash` and `truncated`). `path` is the requested `host:port`. Writes repeat the `command` and set `status` `granted`, `rejected`, `no-auth`, `user-pass` or `no-acceptable-method`. Nothing is dialed or forwarded; the session closes after the tunnel read.
