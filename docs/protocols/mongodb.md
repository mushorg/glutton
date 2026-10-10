# `mongodb` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `header`, `opcode_str`, `command`, `status`, `payload`

`command` is the BSON command name. Writes set `status` `ok`.
