# `mssql` decoded data

Transport: TCP (tcp/1433, and any port where the catch-all sees a TDS PRELOGIN). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `truncated`, plus the fields below when the frame carries them.

| Field | Frame | Meaning |
| --- | --- | --- |
| `command` | read | TDS packet type: `prelogin`, `login7`, `sspi`, `sql_batch`, `rpc`, `attention`, … (`type_0xNN` for unknown types). An RPC after login carries the procedure name instead (`sp_executesql`, `sp_prepexec`, …, or `proc_N` for an unknown ProcID) |
| `client_version`, `encryption`, `instance`, `thread_id` | read `prelogin` | PRELOGIN VERSION (`major.minor.build.subbuild`), ENCRYPTION (`off`/`on`/`not_sup`/`req`), INSTOPT and THREADID options |
| `tds_version` | read `login7` | LOGIN7 TDSVersion, e.g. `0x71000001` (TDS 7.1), `0x74000004` (TDS 7.4) |
| `username`, `hostname`, `app_name`, `server_name`, `client_interface`, `database`, `language`, `client_id` | read `login7` | LOGIN7 strings; `client_id` is the client MAC |
| `password` | read `login7` | The SQL password the client sent, unscrambled (XOR 0xA5, nibble swap) and decoded from UTF-16LE |
| `integrated_auth` | read `login7` | OptionFlags2 `fIntSecurity`: Windows (SSPI) authentication |
| `ntlm_type`, `ntlm_domain`, `ntlm_user`, `ntlm_workstation`, `ntlm_version` | read `login7` / `sspi` | NTLMSSP message type from the SSPI blob; identity and `NTLMv1`/`NTLMv2`/`anonymous` from an AUTHENTICATE. Response hashes are never recorded |
| `query` | read `sql_batch` / `sp_executesql` | Query text after an accepted login (the `sp_executesql` statement for an RPC), cut at 4096 bytes with `truncated` |
| `payload_hash` | read `sql_batch` / RPC | SHA-256 of the whole query text, stored under `payloads/mssql`, when it is longer than 4096 bytes or carries an executable (`0x4D5A…` hex literal or base64 `TVqQ…`) |
| `status` | write | `prelogin`, `sspi-challenge`, `login-failed`, `login-ok`; after login `result` (a result set was sent), `done`, `attention` |
| `error_number` | write `login-failed` | `18456` (login failed for user) or `18452` (untrusted domain / anonymous integrated login) |
| `visit` | write `login-failed` / `login-ok` | The source's `recall` visit number |

`payload` holds the raw TDS packets, headers included; a multi-packet message is one frame. `truncated` is set when the client disconnected mid-message, sent an invalid packet header, or a message passed the cap (64 KiB before login, 1 MiB after); `payload` itself is kept up to 64 KiB, with `truncated` beyond it.

## Emulation

The server poses as SQL Server 2019 (PRELOGIN VERSION 15.0.2000) without encryption support (ENCRYPT_NOT_SUP), so LOGIN7 arrives in the clear.

- SQL authentication LOGIN7 → ERROR 18456 `Login failed for user '<user>'.` + DONE, and the connection closes, until the source has made `mssql.accept_after` (default 3) SQL-auth logins, counted across its connections within a `recall` visit. Brute forcers open one connection per guess, so the next guess (any user and password) is accepted. `mssql.accept_logins: false` rejects every login.
- Integrated LOGIN7 with an NTLM NEGOTIATE → SSPI token with an NTLM CHALLENGE whose TargetInfo carries the sensor's RDP identity (`rdp.computer_name` / `rdp.domain_name`). The client's NTLM AUTHENTICATE (TDS `sspi`) then gets 18456 for `DOMAIN\user`, or 18452 for an anonymous one.
- Integrated LOGIN7 without NTLM (Kerberos) → 18452.
- Any other message before login (SQL batch, RPC, …) is recorded and the connection is closed without a reply.

An accepted login gets the SQL Server login stream: ENVCHANGE database (`master` or the requested one) + INFO 5701, ENVCHANGE collation (SQL_Latin1_General_CP1_CI_AS), ENVCHANGE language + INFO 5703, LOGINACK (`Microsoft SQL Server` 15.0.2000, the client's TDS version up to 7.4), ENVCHANGE packet size, DONE. The session then answers up to 64 requests; nothing in them is executed or fetched:

- `@@VERSION` → one row: SQL Server 2019 RTM 15.0.2000.5 Standard on Windows Server 2019 build 17763 (matching the NTLM VERSION). `@@SERVERNAME` → the sensor's RDP computer name.
- `sp_configure '<option>', <n>` → INFO 15457 `Configuration option '<option>' changed from 0 to <n>. Run the RECONFIGURE statement to install.` (known option prefixes such as `show advanced` are expanded), RETURNSTATUS 0, DONEPROC.
- `xp_cmdshell '<cmd>'` → an `output` column with `nt service\mssqlserver` for `whoami`, the computer name for `hostname`, then the NULL row xp_cmdshell always ends with.
- Everything else (`RECONFIGURE`, `CREATE ASSEMBLY`, `sp_OACreate`, …) → a bare DONE. A batch with several of the statements above gets one reply per statement, in order.
- RPC → the reply to the `sp_executesql` statement, if any, then RETURNSTATUS 0 + DONEPROC. ATTENTION → DONE with DONE_ATTN. A PRELOGIN, LOGIN7 or SSPI after login closes the connection.

Nmap `ms-sql-ntlm-info` (`app_name` `Nmap NSE`, `client_interface` `mssql.lua`) stops after the `sspi-challenge` write: it only wants the CHALLENGE TargetInfo.
