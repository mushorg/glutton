# `ipopts` decoded data

Transport: TCP (packet watcher, not a `rules.yaml` target). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-packet frames: `direction`, `command`, `options`, `malformed`, `payload`, `truncated`

Passive watcher for inbound IPv4 TCP packets whose IP header carries options (IHL > 5). One event per TCP 4-tuple flow. Packets that never reach a userspace handler (dropped by the kernel or by an nftables rule) still appear here: the `AF_PACKET` socket sees them before netfilter's IP hooks. A kernel BPF filter drops every other packet before it reaches userspace.

`command` is a compact TCP flag label (`SYN`, `SYN-ACK`, `ACK`, `RST`, `FIN`, `FIN-ACK`, `PSH-ACK`, or `flags=0x..`). `options` is the IPv4 option list `{type, name, length, data}`; names are IANA labels (EOL, NOP, RR, TS, LSRR, SSRR, SEC, RTRALT, …) and unknown types keep their number. `malformed` is set when an option length is illegal or the header is inconsistent. `payload` is the captured bytes from the IPv4 header onward (snaplen default 256); `truncated` when the IP total length exceeds what was captured.

`direction` is always `read` (attacker → sensor): the socket is bound to IPv4 on `interface`, and the kernel only hands such a socket packets the host receives, never ones it sends.

Flows flush on idle (`ipopts_watch.idle_seconds`, default 5s → `endReason` `timeout`), when `max_frames` is reached, when the flow table is full (`evicted`), or when the watcher stops (`handler_close`). A completed handshake may also produce a normal handler event (possibly with `mptcp`); correlate by src/dst/time — the watcher does not merge them.

Not registered as a conn handler and not matched from `rules.yaml`. Enable or tune via `ipopts_watch.*` in the main config. Opening the capture needs `CAP_NET_RAW` and soft-fails: a warning is logged and the sensor keeps running without the watcher.
