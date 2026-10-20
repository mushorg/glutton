# `ssh` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `truncated`, `version`, `hassh`, `hassh_algorithms`, `user`, `password`, `pubkey_type`, `pubkey_fingerprint`, `variant`, `visit`, `path`, `payload_hash`, `type`, `target`

SSH on tcp/22 and tcp/2222 (minus the management port `ports.ssh`, which is never redirected), and on any port where the catch-all sees a client identification string starting with `SSH-`. The key exchange and authentication use `golang.org/x/crypto/ssh`. The handler records what passes:

| `command` | Direction | Fields |
| --- | --- | --- |
| `banner` | read / write | `version` (identification string without CR LF); `payload` is the wire line. The first frame is the honeypot's banner, so the top-level `payload` is the sensor's banner, not attacker bytes. |
| `kexinit` | read / write | `payload` is the unencrypted SSH_MSG_KEXINIT packet. `hassh` is the [HASSH](https://github.com/salesforce/hassh) (reads) or HASSHServer (writes), `hassh_algorithms` the string that was hashed (`kex;ciphers;macs;compression`). |
| `auth-<method>` | read | `user`; for `password` also `password` (cut at 1024 bytes, with `truncated`); for `publickey` also `pubkey_type` and `pubkey_fingerprint` (`SHA256:…`). |
| `auth-<method>` | write | `status` `failure`, or `success` when the shell opens. No payload: the reply is encrypted. |
| `pty-req` | read | After a login: the client asked for a terminal; `payload` is the request. |
| `shell` | read | After a login: the client asked for an interactive shell. |
| `exec` | read | After a login: a command run without a shell; `payload` is the command line. |
| `write-file` | read | After a login: the shell wrote a file in its in-memory filesystem (`>`, `>>`). `path` is the absolute path, `payload` what was written (cut at 4096 bytes, with `truncated`) and `payload_hash` the SHA-256 of the full content, which is stored under `payloads/ssh` (`helpers.Store`). |
| `channel-open` | read | After a login: a channel other than `session` (`direct-tcpip`, `forwarded-tcpip`, ...) was refused. `type` is the channel type, `target` the `host:port` a forward asked for (never dialed), `payload` the request. |
| `channel-request` | read | After a login: a session request the shell does not serve (`subsystem` such as `sftp`, `x11-req`, `auth-agent-req@openssh.com`), refused. `type` is the request type. |
| `global-request` | read | After a login: a connection-level request (`tcpip-forward`, `no-more-sessions@openssh.com`, ...), refused. `type` and, for forwards, `target` as above. |
| `cmd` | read / write | After a login: `payload` is a line typed in the shell (read) or the fake shell's output (write, `status` `ok`, or `not-found` for an unknown command). Post-login frames hold plaintext, not wire bytes. |

The banner write carries `variant` (the persona) and `visit` (the source's visit number, see `recall`).

A read frame with no `command` holds bytes that do not frame as SSH: text lines before the identification string (one frame), a first packet that is not a KEXINIT, or garbage after the banner. `truncated` marks a frame cut off by the end of the connection.

## Personas

The identification string is one of five systems, picked at random for a source it has not seen and remembered per source IP with `recall` (`ssh.persona` pins one): `ubuntu-22.04` (`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`, shared with the catch-all banner), `ubuntu-20.04`, `ubuntu-24.04`, `debian-12` and `debian-11`. A returning scanner therefore sees the same system until its visit ends (`recall.visit_gap`). The persona sets the banner and what the fake shell reports (hostname, `uname`, `/etc/os-release`, `/proc/cpuinfo`). The offered algorithms are fixed by x/crypto, so the server HASSH is the same for every persona: it offers the OpenSSH 8.9 algorithms that x/crypto implements, without `sntrup761x25519-sha512@openssh.com`, `diffie-hellman-group18-sha512`, umac or `hmac-sha1-etm` MACs, or `zlib@openssh.com`, and `rsa-sha2-256` is listed before `rsa-sha2-512`. Host keys come from `ssh.host_keys` or are generated per process (RSA, ECDSA P-256, Ed25519). Only `publickey` and `password` are offered. Every persona is an OpenSSH that ships strict key exchange (the distributions backported it), because x/crypto always offers `kex-strict-s-v00@openssh.com`; an older persona (CentOS 7's OpenSSH 7.4 was removed for this) would contradict its own KEXINIT. Same-HASSH-for-all-personas remains a tell: matching each version's full algorithm list would need a patched x/crypto.

## Login and fake shell

Password attempts are rejected until the source has made `ssh.accept_after` (default 3) of them, counted across its connections within a `recall` visit, so a bot that tries one password per connection gets in too. The next non-empty password logs in as the user it named, whatever it is. Public keys are always rejected. After 6 failures on one connection (OpenSSH `MaxAuthTries`) the server disconnects with `too many authentication failures` (`endReason` `handler_close`). `ssh.shell: false` restores the reject-everything behavior.

A logged-in client gets up to 4 `session` channels, all on one in-memory filesystem that lives as long as the connection, with a canned bash:

- **Commands:** `whoami`, `id`, `pwd`, `cd`, `ls` (`-l`, `-a`), `cat`, `echo` (`-n`, `-e` with `\xHH` escapes), `mkdir` (`-p`), `touch`, `rm` (`-r`, `-f`), `chmod`, `uname`, `hostname`, `uptime`, `date`, `nproc`, `ps`, `free`, `crontab`, `exit`, plus silent no-ops for `chattr`, `export`, `kill` and the like.
- **Shells:** `sh`, `bash`, `ash` and `dash` (also as `/bin/sh`) run `-c` strings and script files, so the usual `sh -c '...'` one-liners run to the end. A script the client wrote runs too (`sh x`, `./x`). Nesting (`sh -c`, `$(...)`, scripts) stops at depth 3 and a line runs at most 512 commands.
- **Syntax:** `;`, newline, `&`, `&&` and `||` (honoring the exit status), `#` comments, backslash-newline continuations, quotes, `$(...)` and backticks, and the redirections `>`, `>>`, `2>/dev/null`, `2>&1`, `&>`. A pipeline runs only its first command.
- **Files:** the client's writes overlay a few canned `/etc` and `/proc` files. They are capped at 64 KiB and 64 entries (`No space left on device`), recorded as `write-file` frames (see above), and never touch the host.
- **Unknown commands** answer `bash: x: command not found` (exit status 127, `cmd` `status` `not-found`). Downloaders (`wget`, `curl`, `tftp`) fail as if the network were down: the honeypot never fetches or dials anything the client names, so the URL is recorded in the `cmd`/`exec` frame and nothing more.

The connection stays open after a session ends, as a real sshd's does, so a client can run several commands. It closes when the client leaves, when the shell exits, after 256 lines, after the fourth session, or after `ssh.idle_timeout` (default `10s`) without a running session (`endReason` `handler_close`). A session that never asks for a shell or a command also ends after the idle timeout. Port forwards, other channel types and global requests are refused and recorded (`channel-open`, `global-request`, `channel-request`), at most 64 such frames per connection together with `write-file`. Files do not carry over to the source's next connection.
