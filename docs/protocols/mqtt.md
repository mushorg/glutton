# `mqtt` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `packet`, `client_id`, `username`, `password`, `topic`, `topics`, `qos`, `payload`

`command` copies `packet`. CONNECT gets CONNACK accept; CONNECT reads set `client_id`, `username` and `password` when present.

The rule routes tcp/1883 and tcp/8883 here. On any other port the `tcp` catch-all peeks the first bytes and reroutes a CONNECT (type byte `0x10`, a remaining length that covers the variable header, protocol name `MQTT` at level 3, 4 or 5 or `MQIsdp` at level 3) to this handler, so scanners such as nmap that probe moved brokers show up as `mqtt`.
