# `radius` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `identifier`, `username`, `password`, `password_hidden`, `chap_password`, `nas_ip`, `nas_identifier`, `calling_station_id`, `called_station_id`, `message_authenticator`, `status`, `payload`, `truncated`

RADIUS, RFC 2865 authentication (udp/1812) and RFC 2866 accounting (udp/1813). `command` is the packet code name (`Access-Request`, `Accounting-Request`, `Status-Server`, ...), `code_N` for unknown codes, or `malformed` for a datagram shorter than the 20-byte header. `identifier` is the packet identifier (it is always present, `0` is a valid value). A readable header whose length field disagrees with the datagram, or an attribute that runs past the packet, is recorded with `truncated`; attributes parsed before the fault are kept. Bytes past the length field are ignored, as the RFC requires, but stay in `payload`.

Parsed attributes: `username` (User-Name), `nas_ip`, `nas_identifier`, `calling_station_id`, `called_station_id`, `chap_password` (hex of CHAP-Password) and `message_authenticator` (true when the client sent one). User-Password is hidden on the wire with the shared secret, so `password_hidden` is the hex of the attribute as sent and `password` is filled only when it decrypts to printable text with one of a short list of common secrets (`testing123`, `secret`, `radius`, ...). Both are guessing attempts and are recorded in plaintext. Use `payload` (request authenticator plus `password_hidden`) to crack the rest offline.

Access-Request gets a bare 20-byte `Access-Reject` (`status` `reject`), Accounting-Request an `Accounting-Response` (`ok`) and Status-Server an `Access-Accept` (`accept`). The reply echoes the identifier and carries a valid Response Authenticator under a fixed secret, and it is never larger than the request, so the sensor is not an amplifier. Other codes are recorded only. Datagrams over 4096 bytes (the RFC maximum) are capped with `truncated`.

Reflection scanners (e.g. `infrawatch`) send a lone User-Name such as `infragrab-<authenticator hex>@invalid.invalid`, with no password, to see whether anything answers.
