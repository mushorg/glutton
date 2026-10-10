# `mcp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `session_id`, `payload`

`command` is the JSON-RPC method or HTTP verb. Writes set HTTP `status`. Shares the idle session table with HTTP.
