# `mctp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `method`, `cseq`, `func_version`, `segments`, `status`, `return_code`, `payload`, `truncated`

HiSilicon DVR control protocol (tcp/9000). `command` is the `HI_SRDK_*` function, `method` the request method (`REMOTE`), `segments` the number of body data segments. Writes set `status` `200` and `return_code` `0`. Bodies over 64 KiB are stored up to the cap with `truncated`. Non-MCTP traffic on the port falls back to `tcp`.
