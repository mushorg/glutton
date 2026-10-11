# `firebird` decoded data

Transport: TCP (tcp/3050, and any port where the catch-all sees a Firebird `op_connect`). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `payload`, `truncated`, plus the fields below when the frame carries them.

| Field | Frame | Meaning |
| --- | --- | --- |
| `command` | read | Operation: `connect`, `attach`, `create`, `service_attach`, `detach`, `service_detach`, `disconnect`, `exit`, `dummy` (`op_N` for operations that are not parsed) |
| `path` | read `connect` / `attach` / `create` / `service_attach` | Database file or `service_mgr` |
| `operation` | read `connect` | The operation the client is connecting for (`attach`, `create`, `service_attach`) |
| `client_arch` | read `connect` | `p_cnct_client` architecture code, e.g. `36` (Linux), `1` (generic) |
| `protocols` | read `connect` | Offered protocols: `{version, arch, min_type, max_type, weight}`. `version` has the 0x8000 flag stripped (`12`, not `32780`) |
| `os_user`, `client_host` | read `connect` / attach | User identification `CNCT_user`/`CNCT_host`, or DPB `isc_dpb_os_user`/`isc_dpb_host_name` |
| `login`, `auth_plugin` | read `connect` | Firebird 3+ `CNCT_login` and `CNCT_plugin_name` |
| `username` | read attach | DPB/SPB `isc_dpb_user_name` |
| `password` | read `connect` / attach | The password as sent: `CNCT_passwd` on `connect`; DPB/SPB `isc_dpb_password` in plaintext, or the `isc_dpb_password_enc` bytes as sent (as a string) |
| `role`, `charset`, `process_id`, `process_name`, `client_version` | read attach | DPB `isc_dpb_sql_role_name`, `isc_dpb_lc_ctype`, `isc_dpb_process_id`, `isc_dpb_process_name`, `isc_dpb_client_version` |
| `status` | write | `accept`, `reject`, `login_failed` |
| `protocol_version` | write `accept` | Accepted protocol version (10, 11 or 12) |
| `error_code` | write `login_failed` | `335544472` (`isc_login`) |

`payload` holds the raw XDR operation. `truncated` is set when the client disconnected mid-operation, or a length passed the 16 KiB cap.

## Emulation

The server poses as Firebird 2.5. It answers `op_connect` with `op_accept` for the highest-weight protocol 10, 11 or 12 with the generic architecture (packet type capped at `ptype_lazy_send`), or with `op_reject` and a close when none is offered (e.g. only Firebird 3+ protocol 13+). Every `op_attach`, `op_create` and `op_service_attach` after that gets an `op_response` with the status vector `isc_login`, and the connection stays open for further guesses (up to 16 operations). `op_dummy` is ignored. Detach, disconnect, any other operation, or an attach before `op_connect`, is recorded and the connection is closed.

The nmap Firebird probe (also sent by Shodan) is an `op_connect` for `service_mgr` with `os_user` `scanner ` and `client_host` `nmap `, offering protocols 8 and 10. It gets `op_accept` version 10 (`00000003 0000000a 00000001 00000003`) and then hangs up.
