# `ssh` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, `truncated`, `version`, `hassh`, `hassh_algorithms`, `user`, `password`, `pubkey_type`, `pubkey_fingerprint`

SSH on tcp/22 and tcp/2222 (minus the management port `ports.ssh`, which is never redirected), and on any port where the catch-all sees a client identification string starting with `SSH-`. The key exchange and authentication use `golang.org/x/crypto/ssh`. The handler records what passes:

| `command` | Direction | Fields |
| --- | --- | --- |
| `banner` | read / write | `version` (identification string without CR LF); `payload` is the wire line. The first frame is the honeypot's banner, so the top-level `payload` is the sensor's banner, not attacker bytes. |
| `kexinit` | read / write | `payload` is the unencrypted SSH_MSG_KEXINIT packet. `hassh` is the [HASSH](https://github.com/salesforce/hassh) (reads) or HASSHServer (writes), `hassh_algorithms` the string that was hashed (`kex;ciphers;macs;compression`). |
| `auth-<method>` | read | `user`; for `password` also `password` (cut at 1024 bytes, with `truncated`); for `publickey` also `pubkey_type` and `pubkey_fingerprint` (`SHA256:…`). |
| `auth-<method>` | write | `status` `failure`. No payload: the reply is encrypted. |

A read frame with no `command` holds bytes that do not frame as SSH: text lines before the identification string (one frame), a first packet that is not a KEXINIT, or garbage after the banner. `truncated` marks a frame cut off by the end of the connection.

The honeypot presents `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` (shared with the catch-all banner) and offers the OpenSSH 8.9 algorithms that x/crypto implements: no `sntrup761x25519-sha512@openssh.com`, `diffie-hellman-group18-sha512`, umac or `hmac-sha1-etm` MACs, or `zlib@openssh.com`, and `rsa-sha2-256` is listed before `rsa-sha2-512`. Host keys come from `ssh.host_keys` or are generated per process (RSA, ECDSA P-256, Ed25519). Only `publickey` and `password` are offered, as on a stock Ubuntu 22.04 sshd. Every attempt is rejected. After 6 failures (OpenSSH `MaxAuthTries`) the server disconnects with `too many authentication failures` (`endReason` `handler_close`). No session, channel or port forward is ever opened.
