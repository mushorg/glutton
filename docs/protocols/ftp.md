# `ftp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `payload`, `payload_hash`

`command` is the FTP verb. STOR/RETR set `path`. Writes set `status` to the numeric reply code.
