# `mssql` decoded data

Transport: TCP (tcp/1433, and any port where the catch-all sees a TDS PRELOGIN). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `truncated`, plus the fields below when the frame carries them.

| Field | Frame | Meaning |
| --- | --- | --- |
| `command` | read | TDS packet type: `prelogin`, `login7`, `sspi`, `sql_batch`, `rpc`, `attention`, … (`type_0xNN` for unknown types) |
| `client_version`, `encryption`, `instance`, `thread_id` | read `prelogin` | PRELOGIN VERSION (`major.minor.build.subbuild`), ENCRYPTION (`off`/`on`/`not_sup`/`req`), INSTOPT and THREADID options |
| `tds_version` | read `login7` | LOGIN7 TDSVersion, e.g. `0x71000001` (TDS 7.1), `0x74000004` (TDS 7.4) |
| `username`, `hostname`, `app_name`, `server_name`, `client_interface`, `database`, `language`, `client_id` | read `login7` | LOGIN7 strings; `client_id` is the client MAC |
| `password_set` | read `login7` | The client sent a SQL password. The password itself is never decoded or recorded |
| `integrated_auth` | read `login7` | OptionFlags2 `fIntSecurity`: Windows (SSPI) authentication |
| `ntlm_type`, `ntlm_domain`, `ntlm_user`, `ntlm_workstation`, `ntlm_version` | read `login7` / `sspi` | NTLMSSP message type from the SSPI blob; identity and `NTLMv1`/`NTLMv2`/`anonymous` from an AUTHENTICATE. Response hashes are never recorded |
| `status` | write | `prelogin`, `sspi-challenge`, `login-failed` |
| `error_number` | write `login-failed` | `18456` (login failed for user) or `18452` (untrusted domain / anonymous integrated login) |

`payload` holds the raw TDS packets, headers included; a multi-packet message is one frame. `truncated` is set when the client disconnected mid-message, sent an invalid packet header, or a message passed the 64 KiB cap.

## Emulation

The server poses as SQL Server 2019 (PRELOGIN VERSION 15.0.2000) without encryption support (ENCRYPT_NOT_SUP), so LOGIN7 arrives in the clear. It rejects every login and closes:

- SQL authentication LOGIN7 → ERROR 18456 `Login failed for user '<user>'.` + DONE.
- Integrated LOGIN7 with an NTLM NEGOTIATE → SSPI token with an NTLM CHALLENGE whose TargetInfo carries the sensor's RDP identity (`rdp.computer_name` / `rdp.domain_name`). The client's NTLM AUTHENTICATE (TDS `sspi`) then gets 18456 for `DOMAIN\user`, or 18452 for an anonymous one.
- Integrated LOGIN7 without NTLM (Kerberos) → 18452.
- Any other message before login (SQL batch, RPC, …) is recorded and the connection is closed without a reply.

Nmap `ms-sql-ntlm-info` (`app_name` `Nmap NSE`, `client_interface` `mssql.lua`) stops after the `sspi-challenge` write: it only wants the CHALLENGE TargetInfo.
