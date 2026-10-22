# `imap` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `tag`, `command`, `mechanism`, `username`, `password`, `server_name`, `status`, `payload`, `truncated`

IMAP4rev1 (RFC 3501), plaintext on tcp/143 (the greeting goes out on connect, and STARTTLS is offered) or IMAPS on tcp/993 (rule `tls: true`, so TLS details are in the event's `tls` object and the frames are decrypted). The server persona is Dovecot on Ubuntu, the same as the `pop3` handler.

The first frame is always the honeypot's `write` greeting (`status` `OK`): `* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN] Dovecot (Ubuntu) ready.` (no `STARTTLS` under TLS). The top-level `payload` is therefore the greeting, not attacker bytes.

Each client command is a `read` frame with `tag` and the upper-cased `command`. A command with literals (`{n}` or the LITERAL+ form `{n+}`) is folded into one frame whose `payload` holds the whole command; the `+ OK` continuations sent for synchronizing literals are `write` frames with `status` `+` right after it. `LOGIN` records `username` and `password` in plaintext. `AUTHENTICATE` records `mechanism`; for `PLAIN` and `LOGIN` the client's base64 responses are `read` frames with `command` `sasl-response`, and the decoded `username`/`password` are set on the frame that carried them (on the command frame itself when the client used SASL-IR). The `+` prompts are `write` frames with `status` `+`.

Replies are `write` frames whose `status` is the tagged condition. Every login fails with `NO [AUTHENTICATIONFAILED] Authentication failed.`; a `*` SASL response gets `BAD Authentication aborted by client.`; other mechanisms get `NO Unsupported authentication mechanism.` `CAPABILITY`, `ID`, and `NOOP` get `OK`; mailbox commands (`SELECT`, `LIST`, `FETCH`, …) get `BAD … Command not permitted in this state.`; unknown commands get `BAD Error in IMAP command received by server.`, and a line without a tag gets the untagged form. `LOGOUT` gets `* BYE` and `OK`, and the connection closes.

`STARTTLS` on a plaintext connection gets `OK Begin TLS negotiation now.`, then the sensor completes a TLS handshake (shared self-signed certificate) recorded as a `read` frame with `command` `tls`, `server_name` (SNI) and the ClientHello as `payload`; later frames are decrypted. Under TLS it gets `BAD TLS is already active.`

Lines are capped at 4096 bytes and literals at 4096 bytes (`truncated`, the session then ends); up to 32 commands are answered per session (`endReason` `max_frames`). Login failures are answered immediately, without Dovecot's failure delay.
