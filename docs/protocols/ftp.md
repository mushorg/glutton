# `ftp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `username`, `password`, `status`, `payload`, `payload_hash`, `truncated`

`command` is the FTP verb. STOR/RETR set `path`. `USER` sets `username` and `PASS` sets `password`. Writes set `status` to the numeric reply code. `STOR` connects back to the address from the last `PORT` (active mode only) and stores the first read (up to 1 KiB) under `payloads/ftp/`; its read frame carries those bytes and their `payload_hash`. `STOR` without a valid `PORT` gets `425`, and a malformed `PORT` (not six numbers 0–255) gets `501`. A command line longer than 8 KiB keeps its first 8 KiB in `payload` and sets `truncated`; the rest of that line is dropped. A connection keeps at most about 1000 frames; then the event is produced with `endReason` `max_frames`.
