# `postgres` decoded data

Transport: TCP (tcp/5432, and any port where the catch-all sees a PostgreSQL SSLRequest, GSSENCRequest or protocol 3 StartupMessage). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `payload`, `truncated`, plus the fields below when the frame carries them.

| Field | Frame | Meaning |
| --- | --- | --- |
| `command` | read | Untyped first messages: `SSLRequest`, `GSSENCRequest`, `CancelRequest`, `StartupMessage`. Typed messages: `PasswordMessage`, `Query`, `Terminate`, `Parse`, … (`type_0xNN` for unknown types) |
| `command` | write | `SSLResponse`, `GSSENCResponse`, `NegotiateProtocolVersion`, `AuthenticationMD5Password`, `ErrorResponse` |
| `path` | read `StartupMessage` | `database` parameter |
| `protocol_version` | read `StartupMessage` | Requested protocol as `major.minor`, e.g. `3.0`; `1234.5679` for a repeated SSLRequest |
| `user`, `application_name` | read `StartupMessage` | Startup parameters of the same name |
| `params` | read `StartupMessage` | The other startup parameters (`client_encoding`, `options`, `replication`, `_pq_.*`, …) |
| `password` | read `PasswordMessage` | The password string as sent, up to its NUL: under md5 auth `md5` followed by the hex hash, e.g. `md5c0ffee…` |
| `status` | write | `N` on SSL/GSS responses, the SQLSTATE on `ErrorResponse` (`28P01`, `28000`, `0A000`, `08P01`) |
| `message` | write `ErrorResponse` | The `M` field, e.g. `password authentication failed for user "postgres"` |

`payload` holds the raw message, length (and type byte) included, including the `PasswordMessage`. `truncated` is set when the client disconnected mid-message, or a length passed the 10000-byte cap (`MAX_STARTUP_PACKET_LENGTH`); then only the header is kept.

## Emulation

The server poses as a PostgreSQL 15 instance without TLS and with `md5` password authentication:

- SSLRequest and GSSENCRequest get `N` (continue in plaintext), once each. A repeated request is answered like a real server: `FATAL 0A000 unsupported frontend protocol 1234.5679`.
- A StartupMessage for protocol 3.x with a `user` gets `AuthenticationMD5Password` with a random salt. A request for 3.x with x > 0 or with `_pq_.` options first gets `NegotiateProtocolVersion` (3.0, options listed as unsupported).
- Any other protocol version gets `FATAL 0A000`; a missing `user` gets `FATAL 28000`; a parameter list without its terminator is closed without a reply.
- A `PasswordMessage` gets `FATAL 28P01 password authentication failed for user "<user>"`; any other message gets `FATAL 08P01 expected password response`; `Terminate` and `CancelRequest` close the connection. Every login fails; queries are never run.

The common scanner probe is a bare SSLRequest (`00000008 04d2162f`). Credential guessing shows up as `StartupMessage` frames with `user` (often `postgres`) followed by a `PasswordMessage` with `password`.
