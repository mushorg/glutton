# `memcache` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `truncated`

Writes set `status` (`STORED`, `END`, `ERROR`, `CLIENT_ERROR`, `VERSION`). `set` frames aggregate the command line plus the data chunk. A command line longer than 8 KiB keeps its first 8 KiB and sets `truncated`; the rest of that line is dropped.
