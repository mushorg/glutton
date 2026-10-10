# `smb` decoded data

Transport: TCP, ports 445 (Direct TCP) and 139 (NetBIOS session service), same
length-prefixed framing. Covers SMB1 and SMB2. Shared encodings and frame
fields are described in [Logging and producers](../logging.md#decoded-data).

`decoded` is an array of per-direction frames, one event per TCP session.

## Fields

| Field | Set on | Meaning |
| --- | --- | --- |
| `direction` | all | `read` (from attacker) or `write` (from honeypot). |
| `command` | all | Opcode / packet-type name (`SMB_COM_NEGOTIATE`, `SMB2_NEGOTIATE`, `NBSS_SESSION_REQUEST`, …). |
| `header` | SMB1 | Parsed SMB1 header; numeric `tid`/`uid`/`mid`/`pid`, hex `flags2`. |
| `path` | reads | Tree Connect share (`IPC$`), or NT Create AndX filename. |
| `setup` | Trans2 | TRANS2 subcommand name (`TRANS2_SESSION_SETUP`, …). |
| `status` / `nt_status` | writes | NT status name and numeric code. |
| `account` | Session Setup | Client account / NTLM user name (never the password / NTLM response). |
| `domain` / `workstation` | NTLM auth | Domain and workstation from an NTLMSSP AUTHENTICATE. |
| `native_os` / `native_lanman` | Session Setup | Client-advertised OS / LAN Manager strings. |
| `dcerpc` | pipe writes | DCERPC PDU type (`DCERPC_BIND`, `DCERPC_REQUEST`). |
| `interface` / `interface_version` | pipe writes | Bound RPC interface UUID and version. |
| `opnum` | DCERPC request | Operation number of the RPC call. |
| `called_name` / `calling_name` | NBSS session request | Called NetBIOS name (`*SMBSERVER`) / client host name. |
| `total_data_count` | NT Transact reads | Declared total transaction data length. |
| `payload_hash` | read | SHA-256 of stored content: reassembled NT Transact data, a captured file upload (on its NT Create frame), or a DCERPC request stub. |
| `payload` | all | Raw wire bytes, length prefix included. |
| `truncated` | all | A capture cap dropped trailing bytes. |

## Behaviour

**NetBIOS session (port 139).** Control packets get `command`
`NBSS_SESSION_REQUEST` / `NBSS_SESSION_KEEP_ALIVE` / …. A session request sets
`called_name` and `calling_name` and is answered with
`NBSS_POSITIVE_SESSION_RESPONSE`; keepalives get no reply.

**Tree Connect.** `path` is the share. `IPC$` and ordinary shares are accepted;
nmap's `nmap-share-test` probe share is answered with `STATUS_BAD_NETWORK_NAME`.

**Session Setup / NTLM.** Basic Session Setup copies `native_os` / `native_lanman` / `account`. Extended-security Session Setup drives SPNEGO/NTLMSSP: a Type 1 NEGOTIATE is answered with a Type 2 CHALLENGE and `STATUS_MORE_PROCESSING_REQUIRED`; a Type 3 AUTHENTICATE is accepted and its `account` / `domain` / `workstation` recorded. The NTLM challenge-response (credential material) is never parsed or stored. The Negotiate reply advertises extended security only to a client that asked for it.

**NT Create AndX.** `path` is the requested filename. A handle opened on an `IPC$` tree is a named pipe; on any other share it is a disk file.

**Named pipes (DCERPC).** Data written to a pipe is parsed as MS-RPCE. A bind is acknowledged (`dcerpc` `DCERPC_BIND`, with `interface` / `interface_version`) so the client proceeds. A request is logged (`dcerpc` `DCERPC_REQUEST`, `interface`, `opnum`; its stub stored under `payloads/smb/` with the SHA-256 in `payload_hash`) and then answered with a DCERPC fault. No RPC service is emulated — the honeypot captures the call without acting as a backend.

**File uploads.** Bytes written (`WRITE_ANDX` / `WRITE`) to a disk-file handle are buffered (up to 8 MiB) and, on `CLOSE`, stored under `payloads/smb/`; the SHA-256 is set as `payload_hash` on the NT Create read frame.

**Transactions and EternalBlue-class traffic.** Trans2 frames set `setup`. NT
Transact reads set `total_data_count` (sprays often use `0x103d0`). Secondary
fragments (`0x33` / `0x26` / `0xa1`) get no reply until the one that completes an
open NT_TRANSACT (`DataDisplacement + DataCount >= TotalDataCount`), which is
answered with `STATUS_INVALID_PARAMETER`. A session may carry
`SMB_COM_NT_TRANSACT` (`0xa0`) plus many `0x33` sprays rather than only `0xa1` /
SMB2 grooms. The initial NT_TRANSACT data and its secondary fragments are
reassembled by `DataDisplacement` (up to 4 MiB), stored with `helpers.Store`
under `payloads/smb/`, and the SHA-256 is set as `payload_hash` on the
NT_TRANSACT read frame. Echo copies the request data back.

