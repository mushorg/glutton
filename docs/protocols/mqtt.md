# `mqtt` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `packet`, `client_id`, `username`, `topic`, `topics`, `qos`, `payload`

`command` copies `packet`. CONNECT gets CONNACK accept; password bytes are not copied into `decoded`.
