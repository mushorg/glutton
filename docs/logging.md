# Logging And Producers

Last verified against source on 2026-05-15.

Glutton has two output paths that are easy to confuse:

- process logs written through Go `slog`
- optional producer events sent to HTTP or hpfeeds sinks

Handlers can write both, but they are configured separately.

## Process Logs

`producer.NewLogger(...)` creates a JSON `slog` logger. It writes every log record to:

- stdout
- the path configured by `--logpath`

The file writer uses lumberjack rotation with:

| Setting | Value |
| --- | --- |
| Max size | 200 MB |
| Max age | 356 days |
| Compression | true |

Every process log includes the `sensorID` attribute. The sensor ID is read from or written to `<var-dir>/glutton.id`.

The `--debug` flag is parsed, but the current logger uses default `slog.HandlerOptions`, so debug logs are not enabled by that flag in the current implementation.

## Producer Events

Producer events are defined by `producer.Event`:

| JSON field | Meaning |
| --- | --- |
| `timestamp` | UTC event timestamp. |
| `transport` | `tcp` or `udp`. |
| `srcHost` | Source IP address. |
| `srcPort` | Source port. |
| `dstPort` | Original destination port from metadata. |
| `sensorID` | Glutton sensor ID. |
| `rule` | Rule string when metadata includes a rule. |
| `handler` | Handler name supplied by the protocol handler. |
| `payload` | Base64-encoded payload bytes. |
| `scanner` | Scanner classification returned by `scanner.IsScanner(...)`. |
| `decoded` | Handler-specific decoded data. |

Producer events are only sent when:

1. `producers.enabled` is true, so `glutton.Init()` creates a producer.
2. A handler calls `ProduceTCP(...)` or `ProduceUDP(...)`.
3. At least one sink, such as HTTP or hpfeeds, is enabled.

Before producer output, Glutton sanitizes configured public addresses out of the payload by replacing them with `1.2.3.4`.

## HTTP Producer

When `producers.http.enabled` is true, Glutton marshals the event as JSON and sends it with `Content-Type: application/json` to `producers.http.remote`.

Details from source:

- HTTP client timeout is 10 seconds.
- TLS handshake timeout is 5 seconds.
- If the source host is a private IP, the HTTP producer skips the event.
- If the remote URL includes username and password, Glutton uses HTTP Basic Auth.
- The request URL preserves the configured query string.

Example event shape:

```json
{
  "timestamp": "2026-05-15T12:00:00Z",
  "transport": "tcp",
  "srcHost": "203.0.113.10",
  "srcPort": "54321",
  "dstPort": 80,
  "sensorID": "00000000-0000-0000-0000-000000000000",
  "rule": "Rule: tcp",
  "handler": "http",
  "payload": "R0VUIC8gSFRUUC8xLjENCg0K",
  "scanner": "",
  "decoded": {
    "protocol": "http",
    "fields": {}
  }
}
```

The example is illustrative. Handler-specific `decoded` content varies by protocol path.

## hpfeeds Producer

When `producers.hpfeeds.enabled` is true, Glutton connects to the configured hpfeeds broker at startup and publishes gob-encoded `producer.Event` values to `producers.hpfeeds.channel`.

The hpfeeds configuration keys are:

```yaml
producers:
  hpfeeds:
    enabled: false
    host: 172.26.0.2
    port: 20000
    ident: ident
    auth: auth
    channel: test
```

## Handler Logs

Handlers log protocol-specific details. Examples include:

- HTTP method, path, query, source, and destination port.
- TCP payload hashes and payload hex dumps.
- Protocol-specific connection events for services such as SMTP, FTP, Telnet, MongoDB, and SMB.

Treat log payloads as attacker-controlled data.
