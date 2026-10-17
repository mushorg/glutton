# `slp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `xid`, `lang`, `service_type`, `scope`, `predicate`, `url`, `status`, `payload`, `truncated`

Service Location Protocol v2, RFC 2608 (udp/427). `command` is the function name (`SrvRqst`, `SrvTypeRqst`, `AttrRqst`, `SrvReg`, ...), `function_N` for unknown IDs, or `malformed` for a datagram that is not SLPv2 or is shorter than the header. `xid` is the hex transaction ID and `lang` the language tag. A readable header whose length field does not match the datagram, or whose body is cut off, is recorded with `truncated`. For `SrvRqst`, `service_type`, `scope` and `predicate` are the parsed fields; `SrvTypeRqst` fills `service_type` (naming authority) and `scope`; `AttrRqst` fills `url` and `scope`.

Reflection scanners (e.g. `infrawatch`) send a made-up service type and scope carrying a per-probe token; both are recorded as sent. Requests get a `write` frame with the matching reply (`SrvRply`, `SrvTypeRply`, `AttrRply`): an empty answer with `status` `OK`, or `SCOPE_NOT_SUPPORTED` unless the scope list names `default`. The reply echoes the XID and language tag and is always smaller than the request (the handler refuses to send otherwise), so the sensor is not an amplifier. Multicast requests (REQUEST MULTICAST flag) and registrations are recorded only. Datagrams over 1024 bytes are capped with `truncated`.
