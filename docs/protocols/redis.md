# `redis` decoded data

Transport: TCP (tcp/6379, and any port where the catch-all sees a RESP multibulk request, `*N\r\n$`). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `payload`, `truncated`, plus the fields below when the frame carries them.

| Field | Frame | Meaning |
| --- | --- | --- |
| `command` | read | Lowercased command name (`info`, `set`, `slaveof`, `system.exec`, …). Container commands include the subcommand: `config set`, `config get`, `module load`, `client list`, `command docs` |
| `args` | read | Arguments after `command`, as strings: at most 32, each cut to 256 bytes. `payload` always holds the full request |
| `inline` | read | The request was a plain text line (netcat, telnet) rather than a RESP array (redis-cli, client libraries) |
| `path` | read `config set` | The new `dir` or `dbfilename` value (`/var/spool/cron/`, `/root/.ssh`, `authorized_keys`) |
| `path` | read `module load` | The module file, e.g. `/tmp/exp.so` |
| `master` | read `slaveof` / `replicaof` | The replication target as `host:port`. It is never dialed |
| `username`, `password` | read `auth`, `hello`, `migrate` | Credentials as sent: `AUTH <password>`, `AUTH <user> <password>` (Redis 6 syntax), `HELLO 3 AUTH <user> <password>`, `MIGRATE … AUTH`/`AUTH2` |
| `password` | read `config set` | The new `requirepass` or `masterauth` value |
| `status` | write | Simple string text (`OK`, `PONG`, `string`, `none`, `Background saving started`), the error code (`ERR`, `NOSCRIPT`), or `bulk`, `nil`, `integer`, `array` |

A read frame with no `command` is a blank line or an empty array, which gets no reply. `truncated` is set when the client disconnected mid-request, or a request passed the 64 KiB cap; the cap is answered with `-ERR Protocol error` and a close.

## Emulation

The server poses as an unauthenticated Redis 5.0.7 (the Ubuntu 20.04 package) with `protected-mode no`, bound to `0.0.0.0`. Each connection has its own small keyspace (64 keys), so a write chain sees its own `SET`s, and its own `CONFIG` table. The run ID, replication ID, PID and start time are random per sensor process.

- Recon: `PING`, `ECHO`, `INFO [section]` (Server, Clients, Memory, Persistence, Stats, Replication, CPU, Cluster, Keyspace), `CONFIG GET <glob>`, `KEYS`, `SCAN`, `DBSIZE`, `CLIENT LIST|ID|GETNAME|SETNAME`, `COMMAND` (empty), `TIME`, `LASTSAVE`.
- File write chain: `FLUSHALL`/`FLUSHDB`, `SET` (with `NX`/`XX`/`EX`/`PX`), `GET`, `DEL`, `EXISTS`, `TYPE`, `TTL`, `EXPIRE`, then `CONFIG SET dir|dbfilename` and `SAVE`/`BGSAVE` all succeed. Nothing is written to disk.
- Rogue master: `SLAVEOF`/`REPLICAOF host port` returns `+OK` and `INFO replication` shows `role:slave` with `master_link_status:down`, but the honeypot never connects to the master, so the attacker never receives the `PSYNC` it waits for. `MODULE LOAD` fails with `ERR Error loading the extension`, and module commands such as `system.exec` are unknown commands.
- `AUTH` fails with `ERR Client sent AUTH, but no password is set` until the client sets `requirepass`. After that it compares against that value, and the session is not locked.
- `EVAL` scripts that reach for `package`, `io`, `os`, `require`, `loadfile` or `dofile` (CVE-2022-0543 `package.loadlib`) get the patched-server sandbox error. Other scripts get a nil reply, since no Lua runs. `EVALSHA` gets `NOSCRIPT`.
- `QUIT` replies `+OK` and closes; `SHUTDOWN` closes. A request starting with `POST` or `Host:` is closed without a reply, as Redis does against cross-protocol (SSRF) requests.
- Other commands get Redis 5's `ERR unknown command` error, wrong argument counts get `ERR wrong number of arguments`, and malformed RESP gets `ERR Protocol error: …` and a close. A session ends after 64 commands.

Command coverage follows [RedisHoneyPot](https://github.com/cypwnpwnsocute/RedisHoneyPot) (GPL-3.0; no code was taken from it), which emulates the same attack surface. Unlike that project, Glutton sends real RESP integer and null replies (`:1`, `$-1`), not `+(integer) 1` or `+(nil)` strings.

The nmap probe is `*1\r\n$4\r\ninfo\r\n` and gets the full INFO bulk. Cron and SSH-key writers send `FLUSHALL`, `SET <key> "\n\n<cron line or ssh key>\n\n"`, `CONFIG SET dir`, `CONFIG SET dbfilename` and `SAVE`, often pipelined in one segment. The payload is in the `set` frame's `args` and `payload`.
