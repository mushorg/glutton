# `ddp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `version`, `client_type`, `user_credential_present`, `host_type`, `status`, `payload`, `truncated`

PlayStation Device Discovery Protocol (udp/987 PS4, udp/9302 PS5). `command` is `SRCH`, `WAKEUP`, `LAUNCH` or `UNKNOWN`; `version` is the client `device-discovery-protocol-version` on reads and the advertised one on writes. `user_credential_present` records only that a `user-credential` header was sent, never its value. `SRCH` gets a `write` `HTTP/1.1 620 Server Standby` (`status` `620`) from a console identity derived from the sensor address: `host_type` `PS5` for client versions `0003xxxx`, else `PS4`. Replies are limited to one per source IP per minute (the reply is ~3x the probe). `WAKEUP`/`LAUNCH` are recorded only. Datagrams over 1024 bytes are capped with `truncated`.
