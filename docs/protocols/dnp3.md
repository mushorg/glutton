# `dnp3` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `dest`, `src`, `status`, `payload`, `truncated`

DNP3 data link layer. `command` is the link function (`REQUEST_LINK_STATUS`, `TEST_LINK_STATES`, `CONFIRMED_USER_DATA`, …), `BAD_CRC` (header or data-block CRC mismatch) or `UNKNOWN` (not DNP3 / partial). `dest`/`src` are always present (0 is a valid probe address, and the value on `UNKNOWN`/`BAD_CRC` header failures). Writes set `status` (`LINK_STATUS`, `ACK`, `NOT_SUPPORTED`). Capped at 512 read frames; the last kept read is `truncated` and `endReason` is `max_frames`.
