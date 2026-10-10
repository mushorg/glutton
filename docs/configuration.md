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
| `recall.enabled`                                                     | `true`                   | Remembers each source IP's last visit per protocol (in memory only). A source returning after `recall.visit_gap` gets the next response variant; SIP rotates `answer`, `auth`, `busy` (see [logging](logging.md)). `false` answers every visit like the first. |
| `recall.visit_gap`                                                   | `1800`                   | Seconds without activity after which a returning source starts a new visit. Activity within the gap keeps the visit and its variant. |
| `recall.ttl`                                                         | `604800`                 | Seconds a source is remembered after it was last seen. |
| `recall.max_sources`                                                 | `65536`                  | Sources kept in memory; the least recently seen is dropped first. |
| `udp_reply_limit.enabled`                                            | `true`                   | Charges every UDP reply (handlers and `proxy_udp`) against a byte budget for the request's source IP and a global budget, so spoofed requests cannot use the honeypot for reflection/amplification. Replies over budget are dropped; one `Dropping UDP replies over the amplification budget` warning is logged each time a source (or the global budget) becomes limited. The produced event still contains the `write` frame. |
| `udp_reply_limit.source_rate`                                        | `512`                    | Reply bytes per second one source IP may receive. |
| `udp_reply_limit.source_burst`                                       | `8192`                   | Most reply bytes one source IP may receive at once. A reply larger than this is never sent. |
| `udp_reply_limit.global_rate`                                        | `131072`                 | Reply bytes per second to all source IPs together; caps floods spoofed across many victims. `0` disables the global budget. |
| `udp_reply_limit.global_burst`                                       | `1048576`                | Most reply bytes to all source IPs at once. |
| `udp_reply_limit.max_sources`                                        | `65536`                  | Source IPs tracked in memory; the least recently answered is dropped first. |
| `tcp_reply_limit.enabled`                                            | `true`                   | Charges every byte written on a TCP connection (handler replies, TLS records, `proxy_tcp` traffic to the client, and handler-dialed relays such as the VMware `hyper/send` path) against a budget for the peer IP and a global budget. A write over budget is not sent and fails with `guard.ErrLimited`, which ends the session; the handler still produces its event, without the refused `write` frame. One `Dropping TCP replies over the reply budget` warning is logged each time a peer (or the global budget) becomes limited. |
| `tcp_reply_limit.source_rate`                                        | `65536`                  | Bytes per second one peer IP may receive, across all its connections. |
| `tcp_reply_limit.source_burst`                                       | `1048576`                | Most bytes one peer IP may receive at once. A single write larger than this is never sent. |
| `tcp_reply_limit.global_rate`                                        | `8388608`                | Bytes per second to all peers together. `0` disables the global budget. |
| `tcp_reply_limit.global_burst`                                       | `33554432`               | Most bytes to all peers at once. |
| `tcp_reply_limit.max_sources`                                        | `65536`                  | Peer IPs tracked in memory; the least recently answered is dropped first. |
| `sip.reject_invites`                                                 | `2`                      | UDP SIP: the first N new INVITE calls in each visit of a source IP get `404 Not Found`, so toll-fraud tools go on to try more dial prefixes. The count is kept in the recall store and starts over when the source returns after `recall.visit_gap`; with `recall.enabled: false` nothing is rejected. `0` answers every call. |
| `openvpn.reply`                                                      | `false`                  | UDP OpenVPN: reply to a well-formed `P_CONTROL_HARD_RESET_CLIENT_V2` with a `P_CONTROL_HARD_RESET_SERVER_V2` (random session ID, acks the client packet ID; no tls-auth/tls-crypt) so scanners send their follow-up control packets. Malformed resets are never answered. `false` keeps the handler parse-only. |
| `smtp.hostname`                                                      | `mail.localdomain`       | TCP SMTP: the server name in the `220` greeting and the `250` HELO/EHLO reply. |
| `rdp.computer_name`                                                  | *(random `WIN-XXXXX…`)* | TCP RDP: the NetBIOS computer name used in the NTLM Challenge TargetInfo and as the TLS certificate CN. Must be a valid NetBIOS name (≤15 chars). When unset a random `WIN-XXXXXXXXXXX` is generated once per process and reused for all sessions. |
| `rdp.domain_name`                                                    | `WORKGROUP`              | TCP RDP: the NetBIOS domain/workgroup name used in the NTLM Challenge TargetInfo. |
| `dnp3.address`                                                       | `10`                     | TCP DNP3: the outstation link address the handler answers as. `REQUEST_LINK_STATUS` gets `LINK_STATUS`; `RESET_LINK_STATES`, `TEST_LINK_STATES` and `CONFIRMED_USER_DATA` get `ACK`. Frames for any other address (including broadcast) get no reply. Link layer only: no application-layer responses. |
| `spicy.enabled`                                                      | `true`                   | Initializes Spicy/HILTI and enables Spicy-backed paths (HTTP parsing, TCP-payload protocol detection). Set `false` if you build without Spicy or want the Spicy-free dispatch path. |


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
| `tls`     | no       | `conn_handler` only. `true`: the sensor terminates TLS (self-signed cert) before the handler runs, so the handler sees plaintext (implicit TLS such as POP3S on 995); a failed handshake produces one event with the raw client bytes as `payload` and the handler is not run. `auto`: wait up to 500 ms for the client's first bytes; a TLS handshake record (`16 03 00`–`04`) is terminated as with `true`, anything else (plaintext, or a silent client) goes to the handler unchanged. Use `auto` on client-first ports that carry both (MongoDB, MQTT); on server-first protocols it delays the greeting by up to 500 ms. The ClientHello, SNI, ALPN, version and cipher go in the event's `tls` field. |


### Rule types

`**conn_handler**` — `target` is a handler key. Current TCP keys: `smtp`, `rdp`, `smb`, `ftp`, `sip`, `rfb`, `telnet`, `mqtt`, `iscsi`, `bittorrent`, `memcache`, `jabber`, `pop3`, `whois`, `adb`, `mongodb`, `http`, `mcp`, `modbus`, `dnp3`, `opcua`, `mctp`, `dicom`, `proxy_tcp`, `tcp`. UDP keys: `sip`, `openvpn`, `mdns`, `l2tp`, `raknet`, `kerberos`, `coap`, `ike`, `a2s`, `ddp`, `rtps`, `knx`, `dtls`, `wsdiscovery`, `proxy_udp`, `udp`. If the target isn't registered, the listener accepts the connection but no handler runs.

`**proxy_tcp**` — forwards a matched TCP connection to an upstream `host:port`. The address is parsed at rule-load time and stored in rule metadata; at dispatch the proxy handler dials it and pipes bytes both directions. Tunable via `dial_timeout`, `conn_timeout`, `max_tcp_payload`, and `capture_traffic.enabled` in the main config.

`**proxy_udp**` — forwards matched UDP datagrams to an upstream `host:port`, keeping a short-lived flow (keyed by client and original destination) so multi-packet protocols such as QUIC/HTTP3 work. Replies are sent back via TPROXY-sourced `ReplyUDP`. Uses the same `dial_timeout`, `conn_timeout`, `max_tcp_payload`, and `capture_traffic.enabled` knobs as `proxy_tcp` for dial/idle timing and optional sample capture.

### Catch-all interaction with Spicy

The default rules end with `match: tcp` → `target: tcp`, the generic TCP handler peeks at the initial bytes and uses the spicy parser to detect HTTP, RDP, or MongoDB payloads, if detected traffic is routed to a specific handler otherwise it fallback to generic TCP handler. HTTP request lines targeting `/mcp` or `/sse` are routed to the `mcp` handler (Streamable HTTP JSON-RPC) so sessions can continue past `initialize`.

UDP catch-all (`match: udp` → `target: udp`) routes datagrams that start with a SIP request line (`METHOD sip:|sips:|tel:… SIP/2.0`) or status line (`SIP/2.0 NNN`) to `sip` on any port, so SIPVicious-style scans of non-5060 ports get the same replies as `udp dst port 5060`. It also peeks for the RakNet offline magic (`00ffff00fefefefefdfdfdfd12345678`) and routes matching datagrams to `raknet` regardless of destination port. A dedicated `udp dst port 19132` rule also maps to `raknet` before the catch-all. The same catch-all peeks DER APPLICATION 10/12 (AS-REQ/TGS-REQ) and routes those datagrams to `kerberos`; `udp dst port 88` maps to `kerberos` before the catch-all. CoAP version-1 GET/POST/PUT/DELETE datagrams (TKL ≤ 8) are rerouted to `coap`; `udp dst port 5683` maps to `coap` before the catch-all. RTPS (DDS) datagrams (`RTPS` magic, major version 2) are rerouted to `rtps`; `udp dst port 7400`/`7401`/`7410`/`7411` map to `rtps` before the catch-all. Valve Source Engine queries (`ffffffff` followed by `T`/`U`/`V`/`W`/`i`) are rerouted to `a2s`; `udp dst port 27015` maps to `a2s` before the catch-all. PlayStation Device Discovery Protocol requests (`SRCH`/`WAKEUP`/`LAUNCH * HTTP/1.1`) are rerouted to `ddp`; `udp dst port 987 or port 9302` maps to `ddp` before the catch-all. KNXnet/IP datagrams (`06 10` header, a request service type, and a total length equal to the datagram length) are rerouted to `knx`; `udp dst port 3671` maps to `knx` before the catch-all. WS-Discovery SOAP envelopes (XML naming the 2005/04 or 2009/01 discovery namespace) are rerouted to `wsdiscovery`; `udp dst port 3702` maps to `wsdiscovery` before the catch-all. DTLS ClientHello records (content type 22, version `fe ff`/`fe fd`, epoch 0, an unfragmented ClientHello that fits the datagram) are rerouted to `dtls` on any port; there is deliberately no port rule because DTLS ports are arbitrary.