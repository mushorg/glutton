# `nfs` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `xid`, `program`, `version`, `procedure`, `auth`, `machine_name`, `uid`, `gid`, `tag`, `minor_version`, `ops`, `status`, `payload`, `truncated`

ONC RPC (RFC 5531) calls to the NFS program (100003) on tcp/2049. Each message is record-marked: `payload` keeps the 4-byte marks, fragments are reassembled up to 16 KiB (`truncated` past the cap, which ends the session), and up to 32 calls are answered per connection (`endReason` `max_frames` after that). Parsing is shared with [`rpcbind`](rpcbind.md) (`protocols/tcp/oncrpc/`).

Read frames: `command` is `NFSPROC3_*` for version 3 (`NULL`, `GETATTR`, `FSINFO`, …), `NFSPROC4_NULL|COMPOUND` for version 4, `NFSPROC_<n>` for any other version, `CALL` for a call to another program, `REPLY` for an RPC reply and `UNKNOWN` when the message does not parse. `xid`, `program`, `version` and `procedure` come from the call header; `auth` is the credential flavor, and an `AUTH_SYS` credential adds `machine_name`, `uid` and `gid`. An NFSv4 `COMPOUND` also sets `tag`, `minor_version` and `ops` (the operation count; the operations themselves are only in `payload`).

Write frames echo `command` and `xid` and set `status` to the RPC outcome: `SUCCESS`, `PROG_UNAVAIL` (a program other than 100003), `PROG_MISMATCH` (versions 3-4 supported; scanners probe with a bogus version to read this range), `PROC_UNAVAIL`, `GARBAGE_ARGS`, or `RPC_MISMATCH`. `NULL` succeeds. No file system is emulated: v3 `GETATTR`, `ACCESS`, `FSSTAT`, `FSINFO` and `PATHCONF` fail with `NFS3ERR_BADHANDLE`, other v3 procedures answer `PROC_UNAVAIL`, and v4 `COMPOUND` returns an empty result array with `NFS4ERR_ACCESS` (or `NFS4ERR_MINOR_VERS_MISMATCH` for minor versions above 2). The portmapper on tcp/111 does not advertise NFS or mountd yet.
