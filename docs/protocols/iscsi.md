# `iscsi` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `message`, `payload`

`command` is the opcode name (`LOGIN_REQUEST`, `LOGIN_RESPONSE`, …). One produced event per TCP session.
