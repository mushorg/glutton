# `gearman` decoded data

Transport: TCP (default rule: tcp/4730). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `mode`, `command`, `packet_type`, `function`, `unique`, `handle`, `payload`, `truncated`

`mode` is `binary` or `text`. Binary packets have a 12-byte `\0REQ`/`\0RES` header (magic, big-endian type, big-endian size) followed by NUL-separated arguments. Text frames are admin protocol lines.

- **`command`**: for binary frames, the packet type name (`ECHO_REQ`, `SUBMIT_JOB_BG`, `JOB_CREATED`, …, `UNKNOWN_<n>`), with the number in `packet_type`. For text frames, the lowercased first word of the line (`version`, `status`, `workers`, …).
- **`function`, `unique`**: taken from `SUBMIT_JOB*`. `CAN_DO*` also sets `function`.
- **`handle`**: set on `JOB_CREATED`, `GET_STATUS`, `STATUS_RES` and `WORK_*` frames.
- **`payload`**: the raw packet or line.
- **`truncated`**: set for a short header or body, a bad magic, data larger than 64 KiB, or an admin line longer than 4096 bytes. The session ends after a truncated frame.

Binary replies:

- `ECHO_REQ` gets `ECHO_RES` with the same data.
- `SUBMIT_JOB*` gets `JOB_CREATED` with handle `H:<host>:<n>`. No job is run.
- `GET_STATUS` gets `STATUS_RES` with an all-zero status.
- `OPTION_REQ exceptions` gets `OPTION_RES`. Other options get an `ERROR`.
- `GRAB_JOB*` gets `NO_JOB`.
- Worker registration and status packets get no reply.
- Unknown types get `ERROR ERR_UNKNOWN_COMMAND`.

Admin text replies:

- `version` gets `OK 1.1.19.1`, and `getpid` gets `OK <pid>`.
- `status` gets `.`.
- `workers` gets a line for the caller's own connection.
- `maxqueue` and `verbose` get `OK`.
- `shutdown` gets `OK`, then the connection is closed.
- Anything else, HTTP requests included, gets `ERR UNKNOWN_COMMAND Unknown+server+command`.

Each TCP session produces one event and is capped at 64 messages.
