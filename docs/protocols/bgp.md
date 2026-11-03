# `bgp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `header`, `command`, `open`, `notification`, `status`, `payload`

BGP-4 (RFC 4271) session opening on tcp/179. Each message is a 19-byte header (16 × `0xff` marker, big-endian length, type) plus a body. `header` is `{length, type}`. `command` is the type name: `OPEN`, `UPDATE`, `NOTIFICATION`, `KEEPALIVE`, `ROUTE-REFRESH`, else `type-<n>`. On a read OPEN, `open` holds `version`, `as`, `hold_time`, `bgp_id` (dotted quad), `opt_params_len`, `capabilities` (codes from optional parameter type 2) and `as4` (from the four-octet AS capability). `notification` is `{code, subcode, data}` on any NOTIFICATION, read or written. The classic probe is a bare 29-byte OPEN with no optional parameters (Shodan: AS 19384, hold time 180).

Replies (`status` on writes):

- A valid version-4 OPEN gets `open` (AS 65001, hold time 180, the dialed IPv4 address as BGP ID, else `10.0.0.1`; capabilities IPv4 unicast, route refresh, four-octet AS) then `keepalive`.
- A KEEPALIVE after the OPEN gets `keepalive`. UPDATE and ROUTE-REFRESH after the OPEN are recorded and not answered. A NOTIFICATION from the client is recorded and ends the session (`handler_close`).
- Errors get one `notification`, then the session ends. Header errors end with `read_error`: bad marker 1/1, bad length 1/2 (length bytes as data), unknown type 1/3 (type as data). A malformed OPEN gets 2/0, a version other than 4 gets 2/1 (data `00 04`), hold time 1 or 2 gets 2/6, and a second OPEN or a non-OPEN before the OPEN gets 5/0.

A header that fails validation is recorded as a 19-byte `read` without `header`/`command`, and its body is not read. A partial header or body is recorded as is and ends the session from the read error. After 32 messages the session ends with `max_frames`. No routes are advertised or processed. No catch-all reroute exists, so BGP on other ports stays in generic `tcp`.
