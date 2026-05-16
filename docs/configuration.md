# Configuration

Last verified against source on 2026-05-15.

Glutton uses Viper for runtime configuration. The main config file is YAML, and the rules file is YAML with BPF-style match expressions.

## Loading Behavior

Startup uses this sequence:

1. CLI flags are parsed and bound into Viper in `app/server.go`.
2. If `--ssh` is considered set by Viper, `app/server.go` copies it into `ports.ssh`.
3. Glutton looks for `config.yaml` under `--confpath`.
4. If the `--confpath` directory exists, Glutton calls `viper.ReadInConfig()`.
5. If the `--confpath` directory does not exist, Glutton loads the embedded default `config/config.yaml`.
6. Glutton reads `rules_path`; if that file exists, it loads it. Otherwise it loads the embedded default `config/rules.yaml`.

Environment variables are not currently configured as a documented input source. There is no `viper.AutomaticEnv()` call in the current source.

## Main Config

Source file: `config/config.yaml`

```yaml
ports:
  tcp: 5000
  udp: 5001
  ssh: 2222

rules_path: config/rules.yaml

addresses: ["1.2.3.4", "5.4.3.2"]

interface: eth0

producers:
  enabled: false
  http:
    enabled: false
    remote: https://localhost:9000
  hpfeeds:
    enabled: false
    host: 172.26.0.2
    port: 20000
    ident: ident
    auth: auth
    channel: test

conn_timeout: 45
max_tcp_payload: 4096
dial_timeout: 5

capture_traffic:
  enabled: false

spicy:
  enabled: false
```

## Main Config Reference

| Key | Type | Source default | Description |
| --- | --- | --- | --- |
| `ports.tcp` | int | `5000` | Local TCP TPROXY listener port. |
| `ports.udp` | int | `5001` | Local UDP TPROXY listener port. |
| `ports.ssh` | int | `2222` in `config/config.yaml` | Destination port excluded from TPROXY redirection. See SSH default note below. |
| `rules_path` | string | `config/rules.yaml` | Path to the rules YAML file. |
| `addresses` | string list | `["1.2.3.4", "5.4.3.2"]` | Extra public addresses used for payload sanitization and address awareness. |
| `interface` | string | `eth0` | Interface used to discover non-loopback IPs and build TPROXY rules. |
| `producers.enabled` | bool | `false` | Creates the producer object when true. |
| `producers.http.enabled` | bool | `false` | Enables HTTP producer POST output when producers are enabled. |
| `producers.http.remote` | string | `https://localhost:9000` | HTTP producer endpoint. Userinfo in the URL can supply basic auth. |
| `producers.hpfeeds.enabled` | bool | `false` | Enables hpfeeds output when producers are enabled. |
| `producers.hpfeeds.host` | string | `172.26.0.2` | hpfeeds broker host. |
| `producers.hpfeeds.port` | int | `20000` | hpfeeds broker port. |
| `producers.hpfeeds.ident` | string | `ident` | hpfeeds identity. |
| `producers.hpfeeds.auth` | string | `auth` | hpfeeds auth secret. |
| `producers.hpfeeds.channel` | string | `test` | hpfeeds channel. |
| `conn_timeout` | int | `45` | Connection deadline in seconds, refreshed around I/O. Proxy TCP also uses it as the idle I/O timeout. |
| `max_tcp_payload` | int | `4096` | Generic TCP handler payload threshold and proxy TCP per-direction capture cap. |
| `dial_timeout` | int | `5` | Timeout in seconds for opening outbound proxy TCP target connections. |
| `capture_traffic.enabled` | bool | `false` | Enables raw payload capture in proxy TCP logs and produced decoded events. Proxying still forwards traffic when disabled. |
| `spicy.enabled` | bool | `false` | Initializes Spicy/HILTI and enables Spicy-backed paths where wired. The bundled paths are still maturing; enable deliberately. |

## SSH Default Note

There are two source-level defaults for the SSH exclusion port:

- `config/config.yaml` sets `ports.ssh: 2222`.
- `app/server.go` defines `--ssh` with CLI default `22`.

The code only copies `--ssh` into `ports.ssh` when Viper reports the `ssh` key as set. Because this is easy to misread, production deployments should set `ports.ssh` explicitly in config or pass `--ssh` explicitly. Do not rely on an implicit value.

## CLI Flag Reference

| Flag | Config effect |
| --- | --- |
| `--interface`, `-i` | Bound as `interface`. |
| `--ssh`, `-s` | Can override `ports.ssh`. |
| `--logpath`, `-l` | Bound as `logpath` and used by the logger. |
| `--confpath`, `-c` | Bound as `confpath` and used as the config directory. |
| `--debug`, `-d` | Parsed, but not currently wired into `slog.HandlerOptions`. |
| `--version` | Causes the process to print version information and exit before runtime init. |
| `--var-dir` | Directory for persistent `glutton.id`. |

## Rules File

Source file: `config/rules.yaml`

```yaml
rules:
  - match: tcp dst port 23 or port 2323 or port 23231
    type: conn_handler
    target: telnet
  - match: tcp dst port 9889
    type: proxy_tcp
    target: 127.0.0.1:9889
  - match: tcp
    type: conn_handler
    target: tcp
  - match: udp
    type: conn_handler
    target: udp
```

Rules are evaluated in order. The first matching rule wins. See [Rules engine](rules-engine.md) for behavior details.

## Rule Types

| Type | Target meaning | Behavior |
| --- | --- | --- |
| `conn_handler` | Registered handler key such as `http`, `ftp`, `tcp`, or `udp`. | Dispatches traffic to the named local protocol handler. |
| `proxy_tcp` | Upstream TCP target in `host:port` form. | Dials the target and forwards bytes in both directions between the client and upstream service. |
| `drop` | Currently not enforced by listener dispatch. | Accepted by the parser, but not a production drop action in the current listener path. |

`proxy_tcp` produced decoded events use the `proxy_tcp` protocol name and can include one captured payload entry per direction. Captured payload samples are capped by `max_tcp_payload`; when a direction transfers more bytes than the cap, the decoded event is marked as truncated.

## Schema File

`config/schema.json` currently describes the rules document shape, not the full `config/config.yaml` shape. It requires a top-level `rules` array and validates rule fields such as `match`, `type`, `name`, and `target`.
