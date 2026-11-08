# `pcanywhere` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** One `read` frame per datagram (`direction`, `command`, `payload`, `truncated`), followed by one `write` frame (`direction`, `command`, `status`, `payload`) when the handler answers.

Symantec pcAnywhere host discovery on udp/5632. Scanners such as Shodan and Metasploit's `pcanywhere_udp` send the two-byte name query `NQ` or the status query `ST`. `command` is `NQ` or `ST`. Trailing CR, LF or NUL bytes are ignored. Other datagrams on the port are recorded with no `command` and get no reply. Datagrams over 1024 bytes are capped with `truncated`.

Replies:

- `NQ` → `NR` + a 24-byte host name + an 8-byte capability field, both padded with `_` (`status` `NR`, persona host `ACCT-PC01`).
- `ST` → `ST 00 00 43 00` (`status` `available`). The third byte after `ST` is `C` (0x43) for an available host and 0x0b for a busy one.

The reply layout follows the Metasploit `pcanywhere_udp` scanner's parser. It was recalled, not checked against a live host. The length of the `ST` status block and the capability string are guesses.
