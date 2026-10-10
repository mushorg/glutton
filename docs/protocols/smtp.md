# `smtp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `mailbox`, `params`, `username`, `payload`, `truncated`

Reads set `command` to the upper-cased SMTP verb (verbs are case-insensitive). `MAIL FROM`/`RCPT TO` reads set `mailbox` (address without angle brackets) and `params` (ESMTP parameters such as `SIZE=100`). The DATA body is one `DATA` read holding at most 500 lines / 256 KiB; past either cap the rest of the body is read and discarded and the frame sets `truncated`. Client lines keep at most 1024 bytes (`truncated` on the frame when cut). The greeting and HELO/EHLO replies carry `smtp.hostname`. RCPT before MAIL, a nested MAIL, and DATA without an accepted RCPT get `503`; more than 100 recipients get `452`; RSET, HELO/EHLO and a completed DATA reset the transaction. `EHLO` advertises `AUTH PLAIN LOGIN`; AUTH continuation lines are `AUTH` reads, and the frame that carried the identity sets `username` (the password is not stored). Every AUTH attempt is refused with `535`. `STARTTLS` is refused with `454`. Writes set `status` to the 3-digit reply code.
