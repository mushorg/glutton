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
| `conn_timeout`                                                       | `45`                     | Connection deadline in seconds (also the `proxy_tcp` idle I/O timeout).                                                                                                             |
| `max_tcp_payload`                                                    | `4096`                   | Generic TCP handler threshold and `proxy_tcp` per-direction capture cap.                                                                                                            |
| `dial_timeout`                                                       | `5`                      | Outbound `proxy_tcp` dial timeout in seconds.                                                                                                                                       |
| `capture_traffic.enabled`                                            | `false`                  | Enables raw payload capture in `proxy_tcp` logs and produced events. Proxying still forwards traffic when disabled.                                                                 |
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
```


| Field    | Required | Description                                                                          |
| -------- | -------- | ------------------------------------------------------------------------------------ |
| `name`   | no       | Human-readable label. `Rule.String()` returns the `match` expression, not this name. |
| `match`  | yes      | BPF expression compiled with `pcap.NewBPF(...)`.                                     |
| `type`   | yes      | `conn_handler` or `proxy_tcp`.                                                       |
| `target` | yes      | Handler key for `conn_handler`; `host:port` upstream for `proxy_tcp`.                |


### Rule types

`**conn_handler**` — `target` is a handler key. Current TCP keys: `smtp`, `rdp`, `smb`, `ftp`, `sip`, `rfb`, `telnet`, `mqtt`, `iscsi`, `bittorrent`, `memcache`, `jabber`, `adb`, `mongodb`, `http`, `proxy_tcp`, `tcp`. UDP keys: `udp`. If the target isn't registered, the listener accepts the connection but no handler runs.

`**proxy_tcp**` — forwards a matched TCP connection to an upstream `host:port`. The address is parsed at rule-load time and stored in rule metadata; at dispatch the proxy handler dials it and pipes bytes both directions. Tunable via `dial_timeout`, `conn_timeout`, `max_tcp_payload`, and `capture_traffic.enabled` in the main config.

### Catch-all interaction with Spicy

The default rules end with `match: tcp` → `target: tcp`, the generic TCP handler peeks at the initial bytes and uses the spicy parser to detect HTTP, RDP, or MongoDB payloads, if detected traffic is routed to a specific handler otherwise it fallback to generic TCP handler.