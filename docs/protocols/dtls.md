# `dtls` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `client_version`, `session_id`, `cookie_present`, `cookie_valid`, `cipher_suites`, `extensions`, `server_name`, `status`, `payload`, `truncated`

DTLS handshake probes on any UDP port (rerouted from the generic `udp` handler by payload sniff). The `read` frame has `command` `ClientHello` (`UNKNOWN` when the record is truncated or malformed) and `client_version` (`DTLS 1.0`, `DTLS 1.2` or hex). `cipher_suites` are the offered suite IDs, `extensions` the extension types in wire order, `server_name` the SNI. `cookie_present` is set when the hello carried a non-empty cookie and `cookie_valid` when it is the cookie issued to that source address (both absent when false). A hello without a valid cookie gets a `write` `HelloVerifyRequest` (`status` `ok`; 44 bytes, 16-byte HMAC cookie bound to the source IP and port, record sequence echoed from the request), so scanners send the second, cookie-bearing hello, which arrives as its own event. A valid-cookie hello is recorded and not answered: the handshake is not emulated. Datagrams over 1024 bytes are capped with `truncated`.
