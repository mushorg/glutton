# `wdb` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `xid`, `program`, `version`, `procedure`, `auth`, `seq`, `status`, `payload`, `truncated`

Wind River WDB, the VxWorks target debug agent, on udp/17185. WDB is ONC RPC program `0x55555555`, version 1. After the RPC call header, each call carries a parameter wrapper of three XDR words: checksum (`0xffff` followed by a 16-bit ones' complement sum over the message after the XID), size, and sequence number. Parsing uses the shared ONC RPC decoder (`protocols/tcp/oncrpc/`). The WDB wrapper and replies are in `protocols/udp/wdb/`.

Read frames:

- `command` is the WDB procedure name: `WDB_TARGET_PING` (0), `WDB_TARGET_CONNECT` (1), `WDB_TARGET_DISCONNECT` (2), `WDB_TARGET_MODE_SET`/`_GET` (3/4), `WDB_MEM_READ`/`_WRITE` (10/11), or `WDB_PROC_<n>` for any other number.
- `command` is `CALL` for another RPC program, `REPLY` for an RPC reply, and `UNKNOWN` when no call header could be parsed.
- `xid`, `program`, `version`, `procedure` and `auth` come from the RPC header. `seq` is the wrapper's sequence number.

Writes echo `command` and `xid`, and set `status`:

- `SUCCESS` for PING and DISCONNECT, which return an empty reply wrapper with errCode 0.
- `SUCCESS` for CONNECT, which returns a `WDB_TGT_INFO`: agent version `2.0`, runtime VxWorks `5.5.1`, a PPC603 CPU, a big-endian `Wind River SBC8260` BSP with a canned boot line, and 64 MiB of RAM.
- `PROC_UNAVAIL` for memory access and every other procedure. No memory read, write or exploit path is emulated.
- `PROG_UNAVAIL` for other programs, `PROG_MISMATCH` (supported range 1–1) for other versions, and `RPC_MISMATCH` when the RPC version is not 2.

The handler does not reply to RPC replies, calls cut off before the header, or datagrams over 1024 bytes (these set `truncated`). Replies go to the datagram source and count toward `udp_reply_limit`.

The classic probe is a 64-byte `WDB_TARGET_CONNECT` with AUTH_NONE, `seq` 1 and arguments `00000002 00000000 00000000`. Censys sends it with a random XID, and Metasploit's `wdbrpc_version` sends the same call.
