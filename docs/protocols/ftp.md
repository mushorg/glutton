# `ftp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `username`, `password`, `status`, `payload`, `payload_hash`

`command` is the FTP verb. STOR/RETR set `path`. `USER` sets `username` and `PASS` sets `password`. Writes set `status` to the numeric reply code.
