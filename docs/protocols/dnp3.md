# `dnp3` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `dest`, `src`, `status`, `payload`, `truncated`

DNP3 data link layer. `command` is the link function (`REQUEST_LINK_STATUS`, `TEST_LINK_STATES`, `CONFIRMED_USER_DATA`, …), `BAD_CRC` (header or data-block CRC mismatch) or `UNKNOWN` (not DNP3 / partial). `dest`/`src` are always present (0 is a valid probe address, and the value on `UNKNOWN`/`BAD_CRC` header failures). Writes set `status` (`LINK_STATUS`, `ACK`, `NOT_SUPPORTED`). Capped at 512 read frames; the last kept read is `truncated` and `endReason` is `max_frames`.

The `dnp3` rule covers tcp/20000. On other ports the `tcp` catch-all hands a client whose first 10 bytes are a link header with a valid CRC (`05 64 <len≥5> …`) to this handler, so the Censys link-address sweep (`05 64 05 c9 <dest> 0000 <crc>`, dest 0, 1, 2, …, seen on tcp/16464) gets a `LINK_STATUS` from the outstation address.
