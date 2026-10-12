# `pop3` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `username`, `password`, `digest`, `payload`, `truncated`

POP3, plaintext on tcp/110 (plain rule: the greeting goes out on connect, and STLS is not offered) or POP3S on tcp/995 (rule `tls: true`, so TLS details are in the event's `tls` field, not in frames). The greeting `+OK Dovecot (Ubuntu) ready.` is the first `write` frame (`status` `+OK`), so `payload` is the honeypot's banner; the catch-all's port 110 banner uses the same string. `CAPA` lists `TOP`, `USER`, `UIDL`, `RESP-CODES` and `PIPELINING`. Reads set `command` to the upper-cased verb; `USER` also sets `username`, `PASS` sets `password`, and `APOP` sets `username` and `digest`. `PASS`, `APOP` and `AUTH` always fail. A POP3S scanner that sends no ClientHello, or a non-TLS client, produces an event with empty `decoded` (`null`) and the raw bytes as `payload`. Sessions are capped at 32 commands and 4 KiB lines (`truncated`).
