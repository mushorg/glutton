# `cql` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `header`, `command`, `options`, `query`, `username`, `password`, `status`, `payload`, `truncated`

This is the Cassandra native protocol (CQL binary protocol) on tcp/9042. The rule uses `tls: auto`, so client-encrypted sessions are decrypted first. The legacy Thrift RPC on tcp/9160 is the separate [`cassandra`](cassandra.md) handler.

Read frames carry `header` (`version`, `response`, `flags`, `stream`, `opcode`, `length`) and `command`, the opcode name (`OPTIONS`, `STARTUP`, `AUTH_RESPONSE`, `REGISTER`, `QUERY`, `PREPARE`, `EXECUTE`, `BATCH`, or `opcode-<n>`). v1/v2 frames use the 8-byte header with a one-byte stream. The handler also decodes some bodies:

- `options`: the STARTUP string map (`CQL_VERSION`, `DRIVER_NAME`, `DRIVER_VERSION`, `COMPRESSION`, ...)
- `query`: the CQL text of QUERY and PREPARE
- `username`/`password`: the plaintext SASL PLAIN credentials from AUTH_RESPONSE

Bodies of frames with the compression flag are recorded raw and not decoded.

The classic probe is a bare v4 OPTIONS on stream 1 (`04 00 00 01 05 00 00 00 00`, binaryedge), then close.

The handler poses as a stock Cassandra 3.11 node (the release the Thrift handler also impersonates) with `PasswordAuthenticator`. Replies echo the request's version and stream. On writes, `command` is the response opcode and `status` is the outcome:

- `supported`: OPTIONS, in any state, gets SUPPORTED `{COMPRESSION: [snappy, lz4], CQL_VERSION: [3.4.4]}` in 3.11's wire order.
- `authenticate`: STARTUP gets AUTHENTICATE `org.apache.cassandra.auth.PasswordAuthenticator`.
- `auth_success`: any AUTH_RESPONSE succeeds with a null token.
- `ready`: REGISTER after authentication.
- `is_bootstrapping`: after authentication, QUERY, PREPARE, EXECUTE and BATCH get ERROR 0x1002 `Cannot read from a bootstrapping node`.
- `protocol_error`: ERROR 0x000A with Cassandra's message for requests out of order (`Unexpected message QUERY, expecting STARTUP or OPTIONS`, `... expecting SASL_RESPONSE`, a second STARTUP), STARTUP without `CQL_VERSION`, unknown opcodes, response-direction frames, protocol v1/v2, v5 without the `USE_BETA` flag, and a first byte that is not version 1-5. Unknown opcodes, response frames and version errors close the session (`handler_close`).

When the first byte is not a CQL version (TLS without `tls: auto`, HTTP and so on), the read frame has no `header`. Its `payload` is that byte plus whatever the client sent within 250 ms (up to 4 KiB). The reply is a v4 protocol error on stream 0. A partial header is recorded as is, without `header`. A body declared over 64 KiB records only the header with `truncated` and ends with `read_error`. After 32 frames the session ends with `max_frames`. No keyspaces, schema or query results are emulated, and v5 segment framing (Cassandra 4.0+) is not spoken.
