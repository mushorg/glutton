# `slp` decoded data

Transport: UDP and TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `xid`, `lang`, `service_type`, `scope`, `predicate`, `url`, `status`, `payload`, `truncated`

Service Location Protocol v2, RFC 2608 (udp/427 and tcp/427). `command` is the function name (`SrvRqst`, `SrvTypeRqst`, `AttrRqst`, `SrvReg`, `DAAdvert`, ...), `function_N` for unknown IDs, or `malformed` for input that is not SLPv2 or is shorter than the header. `xid` is the hex transaction ID and `lang` the language tag. A readable header whose length field does not match the message, or whose body is cut off, is recorded with `truncated`. For `SrvRqst`, `service_type`, `scope` and `predicate` are the parsed fields; `SrvTypeRqst` fills `service_type` (naming authority) and `scope`; `AttrRqst` fills `url` and `scope`; `DAAdvert` fills `url` (the advertised DA URL) and `scope`.

Reflection scanners (e.g. `infrawatch`) send a made-up service type and scope carrying a per-probe token; both are recorded as sent. Requests get a `write` frame with the matching reply (`SrvRply`, `SrvTypeRply`, `AttrRply`): an empty answer with `status` `OK`, or `SCOPE_NOT_SUPPORTED` unless the scope list names `default`. The reply echoes the XID and language tag. Multicast requests (REQUEST MULTICAST flag), DAAdverts and registrations are recorded only.

## UDP

One datagram per event. The reply is always smaller than the request (the handler refuses to send otherwise), so the sensor is not an amplifier. Datagrams over 1024 bytes are capped with `truncated`.

## TCP

One event per connection with one `read` frame per SLP message, framed by the 24-bit length field (up to 32 messages). Shodan sends a `DAAdvert` (URL `http://<sensor ip>`, scope `DEFAULT`) to tcp/427; like a real SA it gets no reply, and the connection stays open for a follow-up request. A first byte other than version 2 is recorded as one `malformed` read frame holding the 5-byte prefix, and the connection is closed. A length below the 14-byte header or above 4096 bytes is recorded the same way under the function name. A client that closes mid-message leaves a `truncated` read frame with the bytes received (`endReason` `read_error`).
