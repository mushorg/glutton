# `mssql_browser` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** One `read` frame per datagram (`direction`, `command`, `instance`, `payload`, `truncated`), followed by one `write` frame (`direction`, `command`, `status`, `payload`) when the handler answers.

SQL Server Browser (SQL Server Resolution Protocol, MC-SQLR) on udp/1434. Scanners enumerate SQL Server instances with a single `02` byte (CLNT_BCAST_EX) or `03` (CLNT_UCAST_EX), or ask for one instance with `04` followed by a NUL-terminated name (CLNT_UCAST_INST). `command` is `CLNT_BCAST_EX`, `CLNT_UCAST_EX`, `CLNT_UCAST_INST` or `CLNT_UCAST_DAC` (`0f 01` + instance name), and `instance` is the requested name. Other datagrams are recorded with no `command` and get no reply. Datagrams over 1024 bytes are capped with `truncated`.

Replies (`status` `SVR_RESP`): `05`, a little-endian uint16 length, then

```
ServerName;<host>;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.2000.5;tcp;1433;np;\\<host>\pipe\sql\query;;
```

`<host>` is the computer name the `rdp` and `mssql` handlers report, and the version matches the `mssql` handler's `@@version` (SQL Server 2019 RTM). The advertised tcp/1433 is served by `mssql`, so a scanner that follows up lands in that handler.

- `CLNT_BCAST_EX`, `CLNT_UCAST_EX`: always answered.
- `CLNT_UCAST_INST`: answered only for `MSSQLSERVER` (case-insensitive); a real Browser stays silent for an unknown instance.
- `CLNT_UCAST_DAC`: recorded only; the dedicated admin connection is not emulated.
