# `adb` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `packet`, `command`, `args`, `path`, `status`, `identity`, `auth_type`, `sync`, `payload_hash`, `size`, `payload`, `truncated`

Android Debug Bridge over TCP (tcp/5555, tcp/5037). The device persona is an Android 6 TV box with auth disabled: it answers `CNXN` with its own `CNXN`, accepts `shell:`/`exec:` and `sync:` streams, and refuses all other services (`tcp:`, `localabstract:`, `reverse:`, ...) with `CLSE`, so it never dials anything.

- `packet` is the transport message (`CNXN`, `AUTH`, `OPEN`, `OKAY`, `WRTE`, `CLSE`, or hex when unknown). `command` is the leaf operation: the message name for `CNXN`/`AUTH`/`OKAY`/`CLSE`, the service (`shell`, `exec`, `sync`, `tcp`, ...) for `OPEN` and for the `WRTE`s on a stream.
- `args` is the service argument on `OPEN` (the shell command line) and the typed input on interactive shell `WRTE`s. `identity` is the `CNXN` system identity (`host::...` read, `device::...` write). `auth_type` is set on unsolicited `AUTH` reads.
- On `sync` streams (`adb push`), `sync` lists the request ids in the frame (`STAT`, `SEND`, `DATA`, `DONE`, `QUIT`, ...) and `path` the remote path. A pushed file is stored under `payloads/adb/` by SHA-256 (`payload_hash`, `size` = bytes received, `truncated` past 8 MiB). DATA-only `WRTE`s are appended to the frame that opened the file.
- Writes set `status`: `accepted`/`rejected` on the `OPEN` reply, the sync reply id (`OKAY`, `FAIL`, `STAT`, `DONE`) on sync `WRTE`s. The `OKAY` acknowledging every client `WRTE` is flow control and not recorded.
- Raw payloads are kept up to 64 KiB per session (`truncated` beyond). A bad header magic or a `data_length` over 1 MiB ends the session (`endReason` `read_error`).
- A host smart-socket request (`000chost:version`, the adb client to adb server framing) is recorded as one read frame with `command` the service prefix and no `packet`.

Non-ADB traffic on these ports falls back to `tcp`. On any other port the `tcp` catch-all routes a transport `CNXN` here, so adbd moved off 5555 is emulated too.
