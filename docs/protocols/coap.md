# `coap` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `type`, `code`, `code_name`, `message_id`, `token` (hex), `path`, `observe`, `payload`, `truncated`

`command` copies `code_name`. Writes also set `status` (`CONTENT` / `CREATED` / `DELETED`). GET `.well-known/core` returns CoRE Link Format `</ps/temp>,</ps/hum>`. Generic UDP peeks version-1 request codes 1–4 and reroutes here.
