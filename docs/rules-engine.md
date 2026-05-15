# Rules Engine

Last verified against source on 2026-05-15.

Rules decide which handler receives a redirected TCP connection or UDP packet. They live in `config/rules.yaml` by default and are parsed by `rules/rules.go`.

## Rule Shape

```yaml
rules:
  - name: Telnet filter
    match: tcp dst port 23 or port 2323 or port 23231
    type: conn_handler
    target: telnet
```

| Field | Required | Description |
| --- | --- | --- |
| `name` | no | Human-readable rule name. The current `Rule.String()` returns the match expression, not this name. |
| `match` | yes | BPF expression compiled with `pcap.NewBPF(...)`. |
| `type` | yes | Accepted values are `conn_handler` and `drop`. |
| `target` | no | Handler key such as `telnet`, `http`, `tcp`, or `udp`. Required for useful `conn_handler` dispatch. |

## Matching Behavior

Glutton does not run BPF against the original packet bytes. It creates a synthetic Ethernet/IP/TCP or Ethernet/IP/UDP packet from the observed source and destination addresses, then evaluates the configured BPF expression against that synthetic packet.

That means rules are good at matching address and port metadata, for example:

```yaml
rules:
  - match: tcp dst port 3389
    type: conn_handler
    target: rdp
  - match: udp
    type: conn_handler
    target: udp
```

The first matching rule wins.

## Handler Targets

The TCP handler map currently includes:

```text
smtp
rdp
smb
ftp
sip
rfb
telnet
mqtt
iscsi
bittorrent
memcache
jabber
adb
mongodb
http
tcp
```

The UDP handler map currently includes:

```text
udp
```

If a rule target is not registered in the relevant handler map, the current listener code does not run a handler for that connection or packet.

## Catch-All Rules

The default rules end with:

```yaml
  - match: tcp
    type: conn_handler
    target: tcp
  - match: udp
    type: conn_handler
    target: udp
```

The generic TCP handler is important. When Spicy is enabled, that handler path can inspect initial bytes with the `TCP::Protocol` parser and route detected HTTP, RDP, or MongoDB payloads to more specific behavior. Unknown samples fall back to the generic TCP handler.

## Drop Caveat

`rules/rules.go` accepts `type: drop`, but the current TCP and UDP listener paths do not special-case `Drop` after a rule matches. They use the returned rule target for dispatch. Do not rely on `type: drop` as a firewall behavior without testing the current code path or adding explicit listener support.

## Practical Rules

Keep specific rules before broad catch-all rules:

```yaml
rules:
  - match: tcp dst port 25
    type: conn_handler
    target: smtp
  - match: tcp dst port 27017
    type: conn_handler
    target: mongodb
  - match: tcp
    type: conn_handler
    target: tcp
```

If the catch-all `tcp` rule appears first, it will take all TCP traffic before more specific rules can match.
