# `modbus` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `function_code`, `unit_id`, `address`, `quantity`, `status`, `payload`

`command` copies `function_code`. Exception writes set `status` `Exception`.
