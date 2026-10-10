# `l2tp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `message_type`, `message_name`, `host_name`, `vendor_name`, `tunnel_id`, `assigned_tunnel_id`, `ns`, `nr`, `payload`, `truncated`

`command` copies `message_name`. SCCRQ probes get a `write` frame with `status` `SCCRP`.
