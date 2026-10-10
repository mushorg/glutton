# `adb` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of read frames: `direction`, `command`, `payload`, `truncated`

`command` is the service prefix before `:`. Bodies longer than 255 bytes are clipped with `truncated`.
