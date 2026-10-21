# Configuration

Glutton uses Viper. It reads two files from `--confpath`: `config/config.yaml` (main settings) and `config/rules.yaml` (TCP/UDP traffic rounting rules). If either is missing, Glutton falls back to embedded defaults.

For the exact defaults shipped with the binary, see `[config/config.yaml](../config/config.yaml)` and `[config/rules.yaml](../config/rules.yaml)`.

## CLI flags

CLI flags override the matching keys in `config.yaml`.


| Flag          | Short | Default            | Notes                                                                        |
| ------------- | ----- | ------------------ | ---------------------------------------------------------------------------- |
| `--interface` | `-i`  | `eth0`             | Bound as `interface`.                                                        |
| `--ssh`       | `-s`  | `2222`             | Overrides `ports.ssh`. Match this to the port your sshd actually listens on. |
| `--logpath`   | `-l`  | `/dev/null`        | Rotating JSON log file path. Logs also go to stdout.                         |
| `--confpath`  | `-c`  | `config/`          | Directory holding `config.yaml` and `rules.yaml`.                            |
| `--debug`     | `-d`  | `false`            | Parsed and bound, but not yet wired into `slog.HandlerOptions`.              |
| `--version`   | —     | `false`            | Prints version and exits before runtime init.                                |
| `--var-dir`   | —     | `/var/lib/glutton` | Directory for `glutton.id`.                                                  |


## Main config

Source: `config/config.yaml`. Keys you'll most often touch:


| Key                                                                  | Default                  | Description                                                                                                                                                                         |
| -------------------------------------------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ports.tcp`                                                          | `5000`                   | Local TCP TPROXY listener port.                                                                                                                                                     |
| `ports.udp`                                                          | `5001`                   | Local UDP TPROXY listener port.                                                                                                                                                     |
| `ports.ssh`                                                          | `2222`                   | Destination port excluded from TPROXY redirection, added to `ports.ignore.incoming` (see [Ignored ports](#ignored-ports)). `0` adds none.                                                                                            |
| `ports.ignore.incoming` | `[]` | Destination ports excluded from TPROXY redirection: services on this host the honeypot must not take over. At most 15 (with `ports.ssh`). |
| `ports.ignore.outgoing` | `[]` | Source ports excluded from TPROXY redirection: replies from remote services this host connects to (e.g. `53` for DNS). At most 15. |
| `rules_path`                                                         | `config/rules.yaml`      | Path to the rules file.                                                                                                                                                             |
| `addresses`                                                          | `["1.2.3.4", "5.4.3.2"]` | Public addresses used for payload sanitization.                                                                                                                                     |
| `interface`                                                          | `eth0`                   | Interface used for public IP discovery and TPROXY rule installation.                                                                                                                |
| `producers.enabled`                                                  | `false`                  | Creates the producer object.                                                                                                                                                        |
| `producers.http.enabled`                                             | `false`                  | Enables HTTP producer POSTs.                                                                                                                                                        |
| `producers.http.remote`                                              | `https://localhost:9000` | HTTP endpoint. Userinfo in the URL supplies basic auth. Userinfo and query values are redacted from error logs. Non-2xx responses are reported as errors.                          |
| `producers.hpfeeds.enabled`                                          | `false`                  | Enables hpfeeds output.                                                                                                                                                             |
| `producers.hpfeeds.host` / `.port` / `.ident` / `.auth` / `.channel` | —                        | hpfeeds broker connection.                                                                                                                                                          |
| `conn_timeout`                                                       | `45`                     | Connection deadline in seconds (also the `proxy_tcp` / `proxy_udp` idle I/O timeout).                                                                                               |
| `max_tcp_payload`                                                    | `4096`                   | Generic TCP handler threshold and `proxy_tcp` / `proxy_udp` per-direction capture cap.                                                                                              |
| `dial_timeout`                                                       | `5`                      | Outbound `proxy_tcp` / `proxy_udp` dial timeout in seconds.                                                                                                                         |
| `capture_traffic.enabled`                                            | `false`                  | Enables raw payload capture in `proxy_tcp` / `proxy_udp` logs and produced events. Proxying still forwards traffic when disabled.                                                   |
| `recall.enabled`                                                     | `true`                   | Remembers each source IP's last visit per protocol (in memory only). A source returning after `recall.visit_gap` gets the next response variant; SIP rotates `answer`, `progress`, `auth`, `busy`, and a source that leaves an answered call's final response unACKed moves to the next of `progress`, `auth`, `busy` within the visit (see [SIP decoded data](protocols/sip.md)); SMB rotates `clean`, `clean`, `infected`, where `infected` emulates the DoublePulsar implant (see [SMB decoded data](protocols/smb.md)); telnet rotates the BusyBox architecture `arm`, `mips`, `mipsel` (see [telnet decoded data](protocols/telnet.md)); Minecraft rotates the status persona `default`, `smp`, `survival` (see [Minecraft decoded data](protocols/minecraft.md)). `false` answers every visit like the first. |
| `recall.visit_gap`                                                   | `1800`                   | Seconds without activity after which a returning source starts a new visit. Activity within the gap keeps the visit and its variant. |
| `recall.ttl`                                                         | `604800`                 | Seconds a source is remembered after it was last seen. |
| `recall.max_sources`                                                 | `65536`                  | Sources kept in memory; the least recently seen is dropped first. |
| `udp_reply_limit.enabled`                                            | `true`                   | Charges every UDP reply (handlers and `proxy_udp`) against byte and reply-count budgets for the request's source IP and global budgets, so spoofed requests cannot use the honeypot for reflection/amplification. Replies over either budget are dropped; one `Dropping UDP replies over the amplification budget` warning is logged each time a source (or a global budget) becomes limited (`limit` is `source`, `global`, `source_requests`, or `global_requests`). The produced event still contains the `write` frame. |
| `udp_reply_limit.source_rate`                                        | `512`                    | Reply bytes per second one source IP may receive. |
| `udp_reply_limit.source_burst`                                       | `8192`                   | Most reply bytes one source IP may receive at once. A reply larger than this is never sent. |
| `udp_reply_limit.global_rate`                                        | `131072`                 | Reply bytes per second to all source IPs together; caps floods spoofed across many victims. `0` disables the global byte budget. |
| `udp_reply_limit.global_burst`                                       | `1048576`                | Most reply bytes to all source IPs at once. |
| `udp_reply_limit.source_request_rate`                                | `16`                     | Replies per second one source IP may receive. |
| `udp_reply_limit.source_request_burst`                               | `32`                     | Most replies one source IP may receive at once. |
| `udp_reply_limit.global_request_rate`                                | `2048`                   | Replies per second to all source IPs together. `0` disables the global request budget. |
| `udp_reply_limit.global_request_burst`                               | `4096`                   | Most replies to all source IPs at once. |
| `udp_reply_limit.max_sources`                                        | `65536`                  | Source IPs tracked in memory; the least recently answered is dropped first. |
| `tcp_reply_limit.enabled`                                            | `true`                   | Charges every Write on a TCP connection (handler replies, TLS records, `proxy_tcp` traffic to the client, and any connection a handler dials itself) against byte and write-count budgets for the peer IP and global budgets. A write over either budget is not sent and fails with `guard.ErrLimited`, which ends the session; the handler still produces its event, without the refused `write` frame. One `Dropping TCP replies over the reply budget` warning is logged each time a peer (or a global budget) becomes limited (`limit` is `source`, `global`, `source_requests`, or `global_requests`). |
| `tcp_reply_limit.source_rate`                                        | `65536`                  | Bytes per second one peer IP may receive, across all its connections. |
| `tcp_reply_limit.source_burst`                                       | `1048576`                | Most bytes one peer IP may receive at once. A single write larger than this is never sent. |
| `tcp_reply_limit.global_rate`                                        | `8388608`                | Bytes per second to all peers together. `0` disables the global byte budget. |
| `tcp_reply_limit.global_burst`                                       | `33554432`               | Most bytes to all peers at once. |
| `tcp_reply_limit.source_request_rate`                                | `256`                    | Writes per second one peer IP may receive, across all its connections. |
| `tcp_reply_limit.source_request_burst`                               | `512`                    | Most writes one peer IP may receive at once. |
| `tcp_reply_limit.global_request_rate`                                | `16384`                  | Writes per second to all peers together. `0` disables the global request budget. |
| `tcp_reply_limit.global_request_burst`                               | `32768`                  | Most writes to all peers at once. |
| `tcp_reply_limit.max_sources`                                        | `65536`                  | Peer IPs tracked in memory; the least recently answered is dropped first. |
| `sip.reject_invites`                                                 | `2`                      | SIP (UDP, TCP and TLS): the first N new INVITE calls in the first visit of a source IP get `404 Not Found`, so toll-fraud tools go on to try more dial prefixes. Later visits (after `recall.visit_gap`) are never rejected, so a scanner sending one INVITE per visit still sees its variant's outcome. The count is kept in the recall store and starts over only once the source is forgotten (`recall.ttl` or eviction); with `recall.enabled: false` nothing is rejected. `0` answers every call. |
| `sip.register_challenge`                                             | `false`                  | SIP (UDP, TCP and TLS): answer an unauthenticated REGISTER with a `401` digest challenge in every variant; any credentials in the retry are accepted. Records the `username` and digest of REGISTER-only scanners. On UDP the challenge and retry are one event. Off keeps the immediate `200`. |
| `sip.record_media`                                                   | `true`                   | UDP SIP: when the honeypot answers a call with `200 OK`, RTP sent by the caller (from its signaling IP or its offer's `c=` address) to the SDP answer's port is recorded into the call's event instead of producing one `udp` event per packet: one `rtp` summary frame per stream with packet/loss counts and RFC 4733 DTMF digits, and G.711 audio saved as a WAV file under `payloads/rtp/<sha256>`. Recording is passive (nothing is sent back) and capped at 120 s of audio and 4 streams per call and 64 MiB across open calls. `false` leaves caller RTP to the `udp` catch-all. |
| `openvpn.reply`                                                      | `false`                  | UDP OpenVPN: reply to a well-formed `P_CONTROL_HARD_RESET_CLIENT_V2` with a `P_CONTROL_HARD_RESET_SERVER_V2` (random session ID, acks the client packet ID; no tls-auth/tls-crypt) so scanners send their follow-up control packets. Malformed resets are never answered. `false` keeps the handler parse-only. |
| `smtp.hostname`                                                      | `mail.localdomain`       | TCP SMTP: the server name in the `220` greeting and the `250` HELO/EHLO reply. |
| `ssh.host_keys` | `[]` | TCP SSH: private key files (PEM or OpenSSH format) used as host keys. Empty generates RSA 3072, ECDSA P-256 and Ed25519 keys once per process, so host key fingerprints change on every restart; set this to keep them stable. |
| `ssh.shell` | `true` | TCP SSH: open the fake shell after `ssh.accept_after` password attempts from one source. `false` rejects every login. |
| `ssh.accept_after` | `3` | TCP SSH: password attempts from one source (across its connections within a `recall` visit) that fail before the next one logs in. |
| `ssh.idle_timeout` | `10s` | TCP SSH: how long a logged-in connection may stay open without a running session (a Go duration). |
| `ssh.persona` | `""` | TCP SSH: pin one persona (`ubuntu-22.04`, `ubuntu-20.04`, `ubuntu-24.04`, `debian-12`, `debian-11`) instead of picking one per source. |
| `icap.service` | `C-ICAP/0.5.10 server - Echo demo service` | TCP ICAP: the `Service` header in `OPTIONS` replies. |
| `icap.istag` | `CI0001-XXXXXXXXX` | TCP ICAP: the `ISTag` (without quotes) on every reply. The default is what an unconfigured c-icap echo service sends. |
| `rdp.computer_name`                                                  | *(random `WIN-XXXXX…`)* | TCP RDP: the NetBIOS computer name used in the NTLM Challenge TargetInfo and as the TLS certificate CN. Must be a valid NetBIOS name (≤15 chars). When unset a random `WIN-XXXXXXXXXXX` is generated once per process and reused for all sessions. |
| `pve.node_name` | *(random, e.g. `pve1`)* | TCP HTTP on tcp/8006 (Proxmox VE persona): node name in the login page title and the TLS certificate (CN `<node_name>.<domain>`, SAN). When unset one of a few common PVE hostnames is picked once per process. |
| `pve.domain` | *(random, e.g. `lan`)* | Proxmox VE persona: DNS domain of the node certificate CN. When unset one of a few common LAN domains is picked once per process. |
| `rdp.domain_name`                                                    | `WORKGROUP`              | TCP RDP: the NetBIOS domain/workgroup name used in the NTLM Challenge TargetInfo. |
| `rdp.credentials`                                                    | `[]`                     | TCP RDP: optional NLA passwords (`{username, password}`; username is ignored). Needed only for clients that offer CredSSP and not TLS — those cannot complete NLA without a password the sensor knows. A typical TLS\|CredSSP probe is answered with TLS, so any password arrives in Client Info and this list is unused. Empty (the default) is fine. Use weak placeholders only. |
| `rdp.guess_passwords`                                                | `[]`                     | TCP RDP: extra passwords tried against each CredSSP NTLMv2 Authenticate, after `rdp.credentials`. A match completes NLA and the session continues into MCS / Client Info. At most 64 entries are tried. A password on neither list still gets `STATUS_LOGON_FAILURE`: CredSSP's confirmation is sealed with a key derived from the password, so an unknown guess cannot be accepted. Use weak placeholders only. |
| `dnp3.address`                                                       | `10`                     | TCP DNP3: the outstation link address the handler answers as. `REQUEST_LINK_STATUS` gets `LINK_STATUS`; `RESET_LINK_STATES`, `TEST_LINK_STATES` and `CONFIRMED_USER_DATA` get `ACK`. Frames for any other address (including broadcast) get no reply. Link layer only: no application-layer responses. |
| `spicy.enabled`                                                      | `true`                   | Initializes Spicy/HILTI and enables Spicy-backed paths (HTTP parsing, TCP-payload protocol detection). Set `false` if you build without Spicy or want the Spicy-free dispatch path. |

```yaml
rdp:
  credentials:
    - username: administrator
      password: Password1
  guess_passwords:
    - Password1
    - "123456"
```

### Ignored ports

Glutton installs one TPROXY rule per protocol in the `mangle` `PREROUTING` chain. Ports listed here are skipped by it, so that traffic reaches the host instead of the honeypot:

```
-i eth0 -p tcp -m state ! --state ESTABLISHED,RELATED -m multiport ! --dports 22,8022 -m multiport ! --sports 53 -j TPROXY --on-port 5000 --on-ip 127.0.0.1
```

- `ports.ignore.incoming` (plus `ports.ssh`) becomes `! --dports`: new connections to these ports on the host are not redirected.
- `ports.ignore.outgoing` becomes `! --sports`: packets from these remote ports are not redirected, for services the host itself talks to whose replies conntrack does not mark as established.

Each list is sent to iptables `multiport`, which takes at most 15 ports; Glutton refuses to start with more. The same lists are used to remove the rule on shutdown, so don't edit them while Glutton runs.

`ports.ssh` is your management sshd port, so your SSH session survives. Both `ports.ssh` and the CLI flag `--ssh` need to match the port your sshd actually listens on — otherwise the management port will be redirected into the honeypot and you'll lock yourself out.

## Rules

Rules decide which handler receives a redirected TCP connection or UDP packet. They're parsed by `rules/rules.go` and evaluated in order, **first match wins**, so put specific rules before broad catch-alls.

### Rule shape

```yaml
rules:
  - name: Telnet filter
    match: tcp dst port 23 or port 2323 or port 23231
    type: conn_handler
    target: telnet
  - match: tcp dst port 443
    type: proxy_tcp
    target: 127.0.0.1:443
    produce: false
  - match: udp dst port 443
    type: proxy_udp
    target: 127.0.0.1:443
    produce: false
```


| Field     | Required | Description                                                                          |
| --------- | -------- | ------------------------------------------------------------------------------------ |
| `name`    | no       | Human-readable label. `Rule.String()` returns the `match` expression, not this name. |
| `match`   | yes      | BPF expression compiled with `pcap.NewBPF(...)`.                                     |
| `type`    | yes      | `conn_handler`, `proxy_tcp`, or `proxy_udp`.                                         |
| `target`  | yes      | Handler key for `conn_handler`; `host:port` upstream for `proxy_tcp` / `proxy_udp`.  |
| `produce` | no       | When `false`, matching sessions are not sent to producers. Defaults to `true`.       |
| `tls`     | no       | `conn_handler` only. `true`: the sensor terminates TLS (self-signed cert) before the handler runs, so the handler sees plaintext (implicit TLS such as POP3S on 995); on tcp/8006 the certificate is the Proxmox VE node certificate (see `pve.node_name`); a failed handshake produces one event with the raw client bytes as `payload` and the handler is not run. `auto`: wait up to 500 ms for the client's first bytes; a TLS handshake record (`16 03 00`–`04`, or TLCP `16 01 01`) is terminated as with `true`, anything else (plaintext, or a silent client) goes to the handler unchanged. Use `auto` on client-first ports that carry both (MongoDB, MQTT, Proxmox VE on 8006, Nexpose on 3780); on server-first protocols it delays the greeting by up to 500 ms. The ClientHello, SNI, ALPN, version and cipher go in the event's `tls` field. |


### Rule types

`**conn_handler**` — `target` is a handler key. Current TCP keys: `smtp`, `rdp`, `smb`, `ftp`, `sip`, `rfb`, `spice`, `telnet`, `mqtt`, `iscsi`, `bittorrent`, `memcache`, `jabber`, `pop3`, `whois`, `ident`, `rpcbind`, `nfs`, `acpp`, `adb`, `mongodb`, `mssql`, `firebird`, `postgres`, `redis`, `minecraft`, `socks`, `http`, `mcp`, `modbus`, `dnp3`, `enip`, `opcua`, `mctp`, `nvms9000`, `pcom`, `dahua`, `rtsp`, `dicom`, `hl7`, `icap`, `ssh`, `proxy_tcp`, `tcp`. UDP keys: `sip`, `openvpn`, `mdns`, `l2tp`, `raknet`, `kerberos`, `coap`, `ike`, `a2s`, `steam`, `ddp`, `rtps`, `knx`, `enip`, `slp`, `radius`, `itp`, `rip`, `tftp`, `dht`, `snmp`, `dtls`, `wsdiscovery`, `hiflying`, `rpcbind`, `proxy_udp`, `udp`. If the target isn't registered, the listener accepts the connection but no handler runs.

`**proxy_tcp**` — forwards a matched TCP connection to an upstream `host:port`. The address is parsed at rule-load time and stored in rule metadata; at dispatch the proxy handler dials it and pipes bytes both directions. Tunable via `dial_timeout`, `conn_timeout`, `max_tcp_payload`, and `capture_traffic.enabled` in the main config.

`**proxy_udp**` — forwards matched UDP datagrams to an upstream `host:port`, keeping a short-lived flow (keyed by client and original destination) so multi-packet protocols such as QUIC/HTTP3 work. Replies are sent back via TPROXY-sourced `ReplyUDP`. Uses the same `dial_timeout`, `conn_timeout`, `max_tcp_payload`, and `capture_traffic.enabled` knobs as `proxy_tcp` for dial/idle timing and optional sample capture.

### Catch-all interaction with Spicy

The default rules end with `match: tcp` → `target: tcp`, the generic TCP handler peeks at the initial bytes and routes RDP X.224 Connection Requests (TPKT version 3, a TPKT length from 11 to 1024 that agrees with the X.224 length indicator, TPDU type CR) to `rdp` on any port, with or without Spicy, and connections whose first bytes are `SSH-` to `ssh` on any port. Every such detector (SSH, SOCKS, RDP, MSSQL, Firebird, PostgreSQL, ADB, Minecraft, RTSP, SMB, HTTP) is evaluated on the first bytes, and if more than one matches, the target is picked at random and remembered per source IP and destination port (see `recall`), so the same source gets the same target until its visit ends (`recall.visit_gap`). The UDP catch-all behaves the same way. Only when none match, it uses the spicy parser to detect HTTP or MongoDB payloads, if detected traffic is routed to a specific handler otherwise it fallback to generic TCP handler. Detected HTTP that fails Spicy request parsing also falls back to the generic TCP handler. HTTP request lines targeting `/mcp` or `/sse` are routed to the `mcp` handler (Streamable HTTP JSON-RPC) so sessions can continue past `initialize`.

UDP catch-all (`match: udp` → `target: udp`) routes datagrams that start with a SIP request line (`METHOD sip:|sips:|tel:… SIP/2.0`) or status line (`SIP/2.0 NNN`) to `sip` on any port, so SIPVicious-style scans of non-5060 ports get the same replies as `udp dst port 5060`. It also peeks for the RakNet offline magic (`00ffff00fefefefefdfdfdfd12345678`) and routes matching datagrams to `raknet` regardless of destination port. A dedicated `udp dst port 19132` rule also maps to `raknet` before the catch-all. The same catch-all peeks DER APPLICATION 10/12 (AS-REQ/TGS-REQ) and routes those datagrams to `kerberos`; `udp dst port 88` maps to `kerberos` before the catch-all. CoAP version-1 GET/POST/PUT/DELETE datagrams (TKL ≤ 8) are rerouted to `coap`; `udp dst port 5683` maps to `coap` before the catch-all. RTPS (DDS) datagrams (`RTPS` magic, major version 2) are rerouted to `rtps`; `udp dst port 7400`/`7401`/`7410`/`7411` map to `rtps` before the catch-all. Valve Source Engine queries (`ffffffff` followed by `T`/`U`/`V`/`W`/`i`) are rerouted to `a2s`; `udp dst port 27015` maps to `a2s` before the catch-all. Steam Remote Play discovery datagrams (magic `ffffffff214c5fa0`) are rerouted to `steam` (parse-only); `udp dst port 27036` maps to `steam` before the catch-all. PlayStation Device Discovery Protocol requests (`SRCH`/`WAKEUP`/`LAUNCH * HTTP/1.1`) are rerouted to `ddp`; `udp dst port 987 or port 9302` maps to `ddp` before the catch-all. KNXnet/IP datagrams (`06 10` header, a request service type, and a total length equal to the datagram length) are rerouted to `knx`; `udp dst port 3671` maps to `knx` before the catch-all. RIPv1/RIPv2 requests and responses (version 1 or 2, zero header word, length 4 + 20·n with up to 25 entries, AFI 0/2 and metric 1–16) are rerouted to `rip`; `udp dst port 520` maps to `rip` before the catch-all. WS-Discovery SOAP envelopes (XML naming the 2005/04 or 2009/01 discovery namespace) are rerouted to `wsdiscovery`; `udp dst port 3702` maps to `wsdiscovery` before the catch-all. The Hi-Flying Wi-Fi module discovery password (`HF-A11ASSISTHREAD`) is rerouted to `hiflying`, as are `+ok`/`AT+…` datagrams from a source that sent it in the last 5 minutes; `udp dst port 48899` maps to `hiflying` before the catch-all. TFTP RRQ/WRQ requests (opcode 1/2, NUL-terminated filename, a netascii/octet/mail mode, optional option pairs) are rerouted to `tftp`; `udp dst port 69` maps to `tftp` before the catch-all. BitTorrent DHT (BEP 5) queries (bencoded `y=q` with `ping`/`find_node`/`get_peers`/`announce_peer`) are rerouted to `dht`; `udp dst port 6881` maps to `dht` before the catch-all (distinct from TCP `bittorrent` peer handshake on 6969). DTLS ClientHello records (content type 22, version `fe ff`/`fe fd`, epoch 0, an unfragmented ClientHello that fits the datagram) are rerouted to `dtls` on any port; there is deliberately no port rule because DTLS ports are arbitrary. EtherNet/IP list requests (ListIdentity, ListServices or ListInterfaces with status 0 and an encapsulation length equal to the rest of the datagram) are rerouted to `enip` on any port; `udp dst port 44818` maps to `enip` before the catch-all. SLPv2 (`udp dst port 427`) maps to `slp` by port only; there is no catch-all peek. RADIUS (`udp dst port 1812 or port 1813`) maps to `radius` by port only; there is no catch-all peek. SNMPv1/v2c/v3 messages (an outer SEQUENCE spanning the datagram, version 0/1/3, a community string and a PDU tag 0xA0-0xA7, or the v3 msgGlobalData SEQUENCE) are rerouted to `snmp` on any port; `udp dst port 161` maps to `snmp` before the catch-all.