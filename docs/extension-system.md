# Extension System

Last verified against source on 2026-05-15.

Glutton's extension model has three separate layers:

```text
rules
  decide which named target should handle traffic

Go handlers
  own connection lifecycle, logging, producers, and fake responses

Spicy parsers
  extract structured fields from selected byte streams
```

Keeping those layers separate is the main thing to understand before adding a protocol.

## What Can Be Extended

You can extend Glutton by adding:

- a new TCP protocol handler under `protocols/tcp/`
- a new UDP protocol handler under `protocols/udp/`
- a new target in `protocols/protocols.go`
- a new rule in `config/rules.yaml`
- a new Spicy grammar under `protocols/spicy/parsers/`
- handler logic that consumes Spicy parse results
- producer event fields through handler-specific decoded output

## Handler Responsibilities

A Go protocol handler owns runtime behavior:

- read from the connection or packet
- update timeouts when appropriate
- decide what response to write
- log process-level details
- call `ProduceTCP(...)` or `ProduceUDP(...)`
- close the connection when done
- preserve fallback behavior for malformed or unknown input

TCP handlers use this shape:

```go
func HandleExample(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error
```

UDP handlers use this shape:

```go
func HandleExample(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata) error
```

The concrete handler function is registered through `MapTCPProtocolHandlers(...)` or `MapUDPProtocolHandlers(...)` in `protocols/protocols.go`.

## Rule Responsibilities

Rules route traffic before a handler runs. A rule can send traffic to a named target:

```yaml
rules:
  - match: tcp dst port 11211
    type: conn_handler
    target: memcache
```

The target must exist in the relevant handler map. If the target does not exist, the current listener code does not run a handler.

See [Rules engine](rules-engine.md) for matching details and the current `drop` caveat.

## Spicy Responsibilities

Spicy parsers own byte-level structure, not honeypot behavior. A parser can turn raw payload bytes into fields such as:

```text
method
uri.path
headers[0].name
body.content
protocol
```

The Go side still decides how many bytes to read, which parser to call, what to log, which producer event to emit, and what response to write.

Current Spicy-backed paths:

- `HTTP::Request` is registered as parser key `http`.
- `TCP::Protocol` is registered as parser key `tcp`.
- The generic TCP handler path can use `TCP::Protocol` to detect HTTP, RDP, or MongoDB.
- HTTP payloads detected through the generic TCP path can be handled by `protocols/spicy/handlers/http.go`.

A rule target of `http` currently calls the Go HTTP handler in `protocols/tcp/http.go`; it does not automatically select the Spicy HTTP handler.

## Producer Responsibilities

Handlers choose what decoded data to pass to producers. The shared producer event envelope is defined in `producer.Event`, but `decoded` is handler-specific.

If you add a handler, decide:

- what raw payload should be included
- what decoded structure should be stable enough for downstream consumers
- whether public addresses should be sanitized before producer output
- what protocol name should be passed to `ProduceTCP(...)` or `ProduceUDP(...)`

## Tests To Add

For a new handler or parser, add focused tests near the code:

- handler registration tests in `protocols/protocols_test.go` when adding map keys
- handler behavior tests beside the handler package
- parser tests under `protocols/spicy/` for Spicy field contracts
- rules tests under `rules/` if rule behavior changes

Tests should verify both successful parsing/handling and malformed input behavior.
