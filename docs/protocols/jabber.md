# `jabber` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `mechanism`, `username`, `password`, `tls`, `server_name`, `payload`, `truncated`

XMPP client-to-server (tcp/5222, tcp/5223). The honeypot waits for the client (no banner). Frames are split per stanza, not per line. Reads set `command` to the element name (`stream`, `starttls`, `auth`, `iq`, `message`, `stream-end`, ...) and `path` to the stream `to` attribute. Writes use `stream` (header, `path` is `from`), `features` (PLAIN + legacy iq-auth, plus STARTTLS before TLS), `proceed`, `failure`, `iq`, `stream-error`, and `stream-end`; `status` is the condition (`not-authorized`, `invalid-mechanism`, `not-well-formed`, `policy-violation`, `proceed`, `result`). SASL PLAIN `auth` and `jabber:iq:auth` set reads record `username`/`password` (never validated; auth always fails and the stream is closed). A first byte `0x16` (direct TLS, tcp/5223) or STARTTLS adds a `tls` read frame with the raw ClientHello in `payload` and SNI in `server_name`; later frames set `tls` and carry decrypted XML. Frames are capped at 4 KiB (`truncated`) and sessions at 32 reads. Non-XML input is stored as one read frame without `command`.
