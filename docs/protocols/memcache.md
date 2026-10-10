# `memcache` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`

Writes set `status` (`STORED`, `END`, `ERROR`, `CLIENT_ERROR`, `VERSION`). `set` frames aggregate the command line plus the data chunk.
