# `ssh` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `truncated`, `version`, `hassh`, `hassh_algorithms`, `user`, `password`, `pubkey_type`, `pubkey_fingerprint`, `variant`, `visit`

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
| `cmd` | read / write | After a login: `payload` is a line typed in the shell (read) or the fake shell's output (write, `status` `ok`, or `not-found` for an unknown command). Post-login frames hold plaintext, not wire bytes. |

The banner write carries `variant` (the persona) and `visit` (the source's visit number, see `recall`).

A read frame with no `command` holds bytes that do not frame as SSH: text lines before the identification string (one frame), a first packet that is not a KEXINIT, or garbage after the banner. `truncated` marks a frame cut off by the end of the connection.

## Personas

The identification string is one of six systems, picked at random for a source it has not seen and remembered per source IP with `recall` (`ssh.persona` pins one): `ubuntu-22.04` (`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`, shared with the catch-all banner), `ubuntu-20.04`, `ubuntu-24.04`, `debian-12`, `debian-11` and `centos-7`. A returning scanner therefore sees the same system until its visit ends (`recall.visit_gap`). The persona sets the banner and what the fake shell reports (hostname, `uname`, `/etc/os-release`, `/proc/cpuinfo`). The offered algorithms are fixed by x/crypto, so the server HASSH is the same for every persona: it offers the OpenSSH 8.9 algorithms that x/crypto implements, without `sntrup761x25519-sha512@openssh.com`, `diffie-hellman-group18-sha512`, umac or `hmac-sha1-etm` MACs, or `zlib@openssh.com`, and `rsa-sha2-256` is listed before `rsa-sha2-512`. Host keys come from `ssh.host_keys` or are generated per process (RSA, ECDSA P-256, Ed25519). Only `publickey` and `password` are offered.

## Login and fake shell

Password attempts are rejected until the source has made `ssh.accept_after` (default 3) of them, counted across its connections within a `recall` visit, so a bot that tries one password per connection gets in too. The next non-empty password logs in as the user it named, whatever it is. Public keys are always rejected. After 6 failures on one connection (OpenSSH `MaxAuthTries`) the server disconnects with `too many authentication failures` (`endReason` `handler_close`). `ssh.shell: false` restores the reject-everything behavior.

A logged-in client gets up to 4 `session` channels with a canned bash: `whoami`, `id`, `pwd`, `cd`, `ls`, `cat` (a few `/etc` and `/proc` files), `echo`, `uname`, `hostname`, `uptime`, `date`, `nproc`, `ps`, `free`, `crontab`, `exit`, plus silent no-ops for `chmod`, `rm`, `export` and the like. Commands joined with `;`, `&&` or `||` all run, and a pipeline runs only its first command. Anything else answers `command not found`. Downloaders (`wget`, `curl`, `tftp`) fail as if the network were down: the honeypot never fetches or dials anything the client names, so the URL is recorded in the `cmd`/`exec` frame and nothing more. Port forwards and other channel types are rejected, and the connection closes when the shell exits, after 256 lines, or on idle timeout (`endReason` `handler_close`).
