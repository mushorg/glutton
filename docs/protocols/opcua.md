# `opcua` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `message_type`, `service`, `endpoint_url`, `security_policy`, `application_uri`, `application_name`, `username`, `payload`

`command` is `service` (or `message_type` if empty). `path` copies `endpoint_url`. Username identity is recorded; password bytes are not copied into `decoded`.
