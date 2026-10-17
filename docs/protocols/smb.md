# `smb` decoded data

Transport: TCP, ports 445 (Direct TCP) and 139 (NetBIOS session service), same
length-prefixed framing. Covers SMB1 and SMB2. SMB on any other port is also
detected by the catch-all `tcp` handler (an NBSS header followed by `\xffSMB` /
`\xfeSMB`, or an NBSS session request) and handed to this handler, so scanners
that probe moved shares (e.g. Censys on tcp/25026) get a real Negotiate reply. Shared encodings and frame
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
| `account` | Session Setup | Client account / NTLM user name. |
| `password` | basic Session Setup | Plaintext password guess (OEM or Unicode password field that is not a 24-byte or NTLMv2 challenge response). Passwords are guessing attempts and are recorded as sent. |
| `lm_response` / `ntlm_response` | basic Session Setup | Hex of the OEM (LM/LMv2) and Unicode (NTLM/NTLMv2) password fields when they are challenge responses. NTLMSSP (extended security) responses stay in the raw `payload`. |
| `domain` / `workstation` | NTLM auth | Domain and workstation from an NTLMSSP AUTHENTICATE. |
| `native_os` / `native_lanman` | Session Setup | Client-advertised OS / LAN Manager strings. |
| `dcerpc` | pipe writes | DCERPC PDU type (`DCERPC_BIND`, `DCERPC_REQUEST`). |
| `interface` / `interface_version` | pipe writes | Bound RPC interface UUID and version. |
| `opnum` | DCERPC request | Operation number of the RPC call. |
| `called_name` / `calling_name` | NBSS session request | Called NetBIOS name (`*SMBSERVER`) / client host name. |
| `total_data_count` | NT Transact / Trans2 Session Setup reads | Declared total transaction data length. |
| `payload_hash` | read | SHA-256 of stored content: reassembled NT Transact or Trans2 Session Setup data, a captured file upload (on its NT Create frame), or a DCERPC request stub. |
| `shellcode` | read | Heuristic indicators (`pe-dos-stub`, `fstenv-getpc`, `msf-x64-prologue`, …) matched in the reassembled payload; absent when nothing matched. |
| `xor_key` | Trans2 Session Setup reads | Recovered DoublePulsar XOR key (hex), set when the obfuscated payload was successfully de-obfuscated. |
| `decoded_hash` | Trans2 Session Setup reads | SHA-256 of the de-obfuscated DoublePulsar payload, also stored under `payloads/smb/`. |
| `variant` / `visit` | DoublePulsar replies | `clean` or `infected` and the source's visit number, on emulated ping/exec/kill replies only. |
| `payload` | all | Raw wire bytes, length prefix included. |
| `truncated` | all | A capture cap dropped trailing bytes. |

## Behaviour

**NetBIOS session (port 139).** Control packets get `command`
`NBSS_SESSION_REQUEST` / `NBSS_SESSION_KEEP_ALIVE` / …. A session request sets
`called_name` and `calling_name` and is answered with
`NBSS_POSITIVE_SESSION_RESPONSE`; keepalives get no reply.

**Tree Connect.** `path` is the share. `IPC$` and ordinary shares are accepted;
nmap's `nmap-share-test` probe share is answered with `STATUS_BAD_NETWORK_NAME`.

**Session Setup / NTLM.** Basic Session Setup copies `native_os` / `native_lanman` / `account`, plus `password` when the client sent a plaintext password (or `lm_response` / `ntlm_response` hex when it sent challenge responses). Extended-security Session Setup drives SPNEGO/NTLMSSP: a Type 1 NEGOTIATE is answered with a Type 2 CHALLENGE and `STATUS_MORE_PROCESSING_REQUIRED`; a Type 3 AUTHENTICATE is accepted and its `account` / `domain` / `workstation` recorded. The NTLMSSP challenge-response is not decoded; it remains in the raw `payload`. The Negotiate reply advertises extended security only to a client that asked for it.

**NT Create AndX.** `path` is the requested filename. A handle opened on an `IPC$` tree is a named pipe; on any other share it is a disk file.

**Named pipes (DCERPC).** Data written to a pipe is parsed as MS-RPCE. A bind is acknowledged (`dcerpc` `DCERPC_BIND`, with `interface` / `interface_version`) so the client proceeds. A request is logged (`dcerpc` `DCERPC_REQUEST`, `interface`, `opnum`; its stub stored under `payloads/smb/` with the SHA-256 in `payload_hash`) and then answered with a DCERPC fault. The one exception is `srvsvc` `NetrShareEnum` (opnum 15, info level 0 or 1), which is answered with a fixed, fake share table (`ADMIN$`, `C$`, `DEMO`, `IPC$`, `TMP`; list in `protocols/tcp/smb/srvsvc.go`) so share-enumeration tools (`smbclient -L`, `net view`, nmap `smb-enum-shares`) continue to the next stage. Other levels and operations still fault. No real RPC service is emulated — the honeypot captures the call without acting as a backend.

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

**DoublePulsar (Trans2 Session Setup).** The DoublePulsar implant protocol
smuggles its payload through `SMB_COM_TRANSACTION2` with the `TRANS2_SESSION_SETUP`
subcommand, obfuscated with a repeating 4-byte XOR key and (for larger payloads)
split across `TRANSACTION2_SECONDARY` fragments. The command is the sum of the
four bytes of the request's Timeout field: ping `0x23`, exec `0xc8`, kill `0x77`
(only exec is confirmed against a published capture). The request data is
reassembled the same way as NT_TRANSACT, whatever the honeypot replies, and stored
under `payloads/smb/`.

The reply depends on the recall variant of the source (`recall.enabled` must be
on; with it off every visit is `clean`). A first visit is `clean`: Session Setup
gets `STATUS_NOT_IMPLEMENTED`. Variants rotate `clean`, `clean`, `infected`, so
about one in three returning visits (3, 6, 9, ...) presents as an infected host:

- ping: `STATUS_SUCCESS` with Multiplex ID = request MID + `0x10` and a random
  8-byte signature in the SMB header. The operator derives the XOR key from that
  signature, so the honeypot knows it too.
- exec: acknowledged the same way (on the final `TRANSACTION2_SECONDARY` for a
  fragmented payload). The payload is decrypted with the known key; no brute force.
- kill/uninstall: acknowledged, and the known key is forgotten.

The emulated reply frames carry `variant` and `visit`. Without a ping (clean visit
or exec first) the key is unknown: the key the operator embedded in the exec
parameters is tried, then every 16-bit signature seed, keeping the one whose
plaintext scores highest in the shellcode heuristics. On success the read frame
gets `xor_key`, the de-obfuscated payload is stored and its hash set as
`decoded_hash`, and `shellcode` reflects the decoded bytes.

**Shellcode heuristics.** Every reassembled transaction payload (NT_TRANSACT
overflow data and decoded DoublePulsar payloads) is scanned for common
x86/x64 shellcode and embedded-PE indicators (`helpers.DetectShellcode`); matches
are listed in `shellcode`. This is advisory triage, not a verdict.

