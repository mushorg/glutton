# `mqtt` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `packet`, `client_id`, `username`, `password`, `topic`, `topics`, `qos`, `payload`

`command` copies `packet`. CONNECT gets CONNACK accept; CONNECT reads set `client_id`, `username` and `password` when present.
