# `dns` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `id`, `opcode`, `command`, `class`, `path`, `status`, `payload`, `truncated`

DNS over TCP (tcp/53, RFC 7766): each message carries a 2-byte length prefix, and `payload` holds the raw bytes including that prefix. A `read` frame sets `id` (the DNS message ID), `command` (the query type: `A`, `AAAA`, `ANY`, `AXFR`, `TXT`, ... or `TYPEnnn`) and `path` (the query name, with non-printable bytes written as `\DDD`). `class` is set only when it is not `IN` (`CH` for `version.bind` probes), and `opcode` only when it is not a plain query (`iquery`, `status`, `notify`, `update`).

The honeypot answers like a non-recursive name server and never resolves or forwards anything. The `write` frame `status` is the response code:

| `status` | When |
| --- | --- |
| `REFUSED` | Every real query, including `AXFR` and recursion requests. Recursion available (`RA`) is never set. |
| `NOTIMP` | An opcode other than QUERY. |
| `FORMERR` | A header with a missing or malformed question (compression pointer, label over 63 bytes, truncated name). The reply is a bare header. |
| `BADVERS` | An EDNS version other than 0. |

The reply echoes the question as sent and, for an EDNS query, an empty OPT record (UDP size 1232), so it is never larger than the query. A message with the `QR` bit set is a response; it is recorded but not answered. Up to 8 messages are answered per connection (`endReason` `max_frames` after that). A message shorter than a 12-byte header is recorded and the connection closes with no reply. If the client announces a length but stops early (a non-DNS protocol on port 53, such as HTTP), the bytes that arrived are stored in one `read` frame with `truncated` set and `endReason` `read_error`. A client that sends nothing yields an empty array.

UDP port 53 is not handled here; datagrams there reach the generic `udp` handler.
