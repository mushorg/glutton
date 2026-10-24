# `rsync` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `version`, `digests`, `username`, `response`, `payload`, `truncated`

rsync daemon protocol (rsyncd) on tcp/873. A `@RSYNCD: ` version line sent first to any other port is routed here from the catch-all too. The honeypot greets first with `@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4` (rsync 3.2.x), the first `write` frame with `status` `greeting`, so the top-level `payload` is the honeypot's banner. The dialog then follows the daemon:

- The client's version line becomes a `read` frame with `command` `version`, `version` (e.g. `31.0`) and, for protocol 30+ clients, the offered auth `digests`. Any other first line gets `@ERROR: protocol startup error` (`status` `protocol-error`, no `command` on the read).
- An empty line or `#list` (`command` `list`) gets the module list (`backup`, `www`, `data`, each `name<TAB>comment`) and `@RSYNCD: EXIT` (`status` `list`).
- A module name (`command` `module`, `path` the module) that is listed gets `@RSYNCD: AUTHREQD <challenge>` (`status` `authreqd`); any other name gets `@ERROR: Unknown module '<name>'` (`status` `unknown-module`).
- The client's auth reply (`command` `auth`, `path` the module) sets `username` and `response`, the base64 digest of the password and the challenge, in plaintext as sent. It always gets `@ERROR: auth failed on module <name>` (`status` `auth-failed`).

The connection closes after every reply except the challenge, as rsyncd does. No module is ever opened and no file data is sent. Lines over 4 KiB are recorded with `truncated` and end the session.
