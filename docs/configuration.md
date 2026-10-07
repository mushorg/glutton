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
| `ports.ssh`                                                          | `2222`                   | Destination port excluded from TPROXY redirection (see [SSH exclusion](#ssh-exclusion)).                                                                                            |
| `rules_path`                                                         | `config/rules.yaml`      | Path to the rules file.                                                                                                                                                             |
| `addresses`                                                          | `["1.2.3.4", "5.4.3.2"]` | Public addresses used for payload sanitization.                                                                                                                                     |
| `interface`                                                          | `eth0`                   | Interface used for public IP discovery and TPROXY rule installation.                                                                                                                |
| `producers.enabled`                                                  | `false`                  | Creates the producer object.                                                                                                                                                        |
| `producers.http.enabled`                                             | `false`                  | Enables HTTP producer POSTs.                                                                                                                                                        |
| `producers.http.remote`                                              | `https://localhost:9000` | HTTP endpoint. Userinfo in the URL supplies basic auth.                                                                                                                             |
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
| `sip.reject_invites`                                                 | `2`                      | UDP SIP: the first N new INVITE calls in each visit of a source IP get `404 Not Found`, so toll-fraud tools go on to try more dial prefixes. The count is kept in the recall store and starts over when the source returns after `recall.visit_gap`; with `recall.enabled: false` nothing is rejected. `0` answers every call. |
| `spicy.enabled`                                                      | `true`                   | Initializes Spicy/HILTI and enables Spicy-backed paths (HTTP parsing, TCP-payload protocol detection). Set `false` if you build without Spicy or want the Spicy-free dispatch path. |


### SSH exclusion

`ports.ssh` is the destination port iptables skips when redirecting traffic into the honeypot, so your management SSH session survives. Both `ports.ssh` (default `2222`) and the CLI flag `--ssh` (default `2222`) need to match the port your sshd actually listens on. If your sshd is on `22`, pass `--ssh 22` or set `ports.ssh: 22` before exposing the sensor — otherwise the management port will be redirected into the honeypot and you'll lock yourself out.

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


### Rule types

`**conn_handler**` — `target` is a handler key. Current TCP keys: `smtp`, `rdp`, `smb`, `ftp`, `sip`, `rfb`, `telnet`, `mqtt`, `iscsi`, `bittorrent`, `memcache`, `jabber`, `pop3s`, `whois`, `adb`, `mongodb`, `http`, `mcp`, `modbus`, `opcua`, `mctp`, `dicom`, `proxy_tcp`, `tcp`. UDP keys: `sip`, `openvpn`, `mdns`, `l2tp`, `raknet`, `kerberos`, `coap`, `ike`, `a2s`, `ddp`, `proxy_udp`, `udp`. If the target isn't registered, the listener accepts the connection but no handler runs.

`**proxy_tcp**` — forwards a matched TCP connection to an upstream `host:port`. The address is parsed at rule-load time and stored in rule metadata; at dispatch the proxy handler dials it and pipes bytes both directions. Tunable via `dial_timeout`, `conn_timeout`, `max_tcp_payload`, and `capture_traffic.enabled` in the main config.

`**proxy_udp**` — forwards matched UDP datagrams to an upstream `host:port`, keeping a short-lived flow (keyed by client and original destination) so multi-packet protocols such as QUIC/HTTP3 work. Replies are sent back via TPROXY-sourced `ReplyUDP`. Uses the same `dial_timeout`, `conn_timeout`, `max_tcp_payload`, and `capture_traffic.enabled` knobs as `proxy_tcp` for dial/idle timing and optional sample capture.

### Catch-all interaction with Spicy

The default rules end with `match: tcp` → `target: tcp`, the generic TCP handler peeks at the initial bytes and uses the spicy parser to detect HTTP, RDP, or MongoDB payloads, if detected traffic is routed to a specific handler otherwise it fallback to generic TCP handler. HTTP request lines targeting `/mcp` or `/sse` are routed to the `mcp` handler (Streamable HTTP JSON-RPC) so sessions can continue past `initialize`.

UDP catch-all (`match: udp` → `target: udp`) routes datagrams that start with a SIP request line (`METHOD sip:|sips:|tel:… SIP/2.0`) or status line (`SIP/2.0 NNN`) to `sip` on any port, so SIPVicious-style scans of non-5060 ports get the same replies as `udp dst port 5060`. It also peeks for the RakNet offline magic (`00ffff00fefefefefdfdfdfd12345678`) and routes matching datagrams to `raknet` regardless of destination port. A dedicated `udp dst port 19132` rule also maps to `raknet` before the catch-all. The same catch-all peeks DER APPLICATION 10/12 (AS-REQ/TGS-REQ) and routes those datagrams to `kerberos`; `udp dst port 88` maps to `kerberos` before the catch-all. CoAP version-1 GET/POST/PUT/DELETE datagrams (TKL ≤ 8) are rerouted to `coap`; `udp dst port 5683` maps to `coap` before the catch-all. Valve Source Engine queries (`ffffffff` followed by `T`/`U`/`V`/`W`/`i`) are rerouted to `a2s`; `udp dst port 27015` maps to `a2s` before the catch-all. PlayStation Device Discovery Protocol requests (`SRCH`/`WAKEUP`/`LAUNCH * HTTP/1.1`) are rerouted to `ddp`; `udp dst port 987 or port 9302` maps to `ddp` before the catch-all.