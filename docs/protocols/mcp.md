# `mcp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `session_id`, `payload`

`command` is the JSON-RPC method or HTTP verb. Writes set HTTP `status`. Shares the idle session table with HTTP, including its limits (500 frames, 8 MiB or one hour per event, then a new event under the same `Mcp-Session-Id`; 1024 tracked sessions, with the idlest evicted as `endReason` `evicted`). Request line plus headers are capped at 64 KiB, as for [`http`](http.md#sessions).
