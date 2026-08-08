# Extension system

Glutton's extension model has three layers, kept deliberately separate:

```text
rules           decide which named target should handle traffic
Go handlers     own connection lifecycle, logging, producers, and fake responses
Spicy parsers   extract structured fields from selected byte streams
```

Most extensions are a Go handler plus a rule. A Spicy parser is optional and only worthwhile when byte-level field extraction will be reused downstream. See [Adding a protocol](protocols/adding-a-protocol.md) for the end-to-end walkthrough.

## Handler responsibilities

A Go protocol handler owns runtime behavior:

- read from the connection or packet
- update timeouts when appropriate
- decide what response to write
- log process-level details
- call `ProduceTCP(...)` or `ProduceUDP(...)`
- close the connection when done
- preserve fallback behavior for malformed or unknown input

TCP handler shape:

```go
func HandleExample(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error
```

UDP handler shape:

```go
func HandleExample(ctx context.Context, srcAddr, dstAddr *net.UDPAddr, data []byte, md connection.Metadata) error
```

Registration happens through `MapTCPProtocolHandlers(...)` or `MapUDPProtocolHandlers(...)` in `protocols/protocols.go`.

## Rule responsibilities

Rules route traffic before a handler runs. A `conn_handler` rule sends traffic to a registered handler key; a `proxy_tcp` rule sends it to an upstream `host:port`:

```yaml
rules:
  - match: tcp dst port 11211
    type: conn_handler
    target: memcache
  - match: tcp dst port 9889
    type: proxy_tcp
    target: 127.0.0.1:9889
```

If the `conn_handler` target isn't registered in the handler map, the listener doesn't run a handler. See [Configuration → Rules](configuration.md#rules) for matching details.

## Spicy responsibilities

Spicy parsers own byte-level structure, not honeypot behavior. A parser turns raw payload bytes into named fields like `method`, `uri.path`, `headers[0].name`. The Go side still decides how many bytes to read, which parser to call, what to log, which producer event to emit, and what response to write.

Current Spicy-backed paths:

- `HTTP::Request` is registered as parser key `http`.
- `TCP::Protocol` is registered as parser key `tcp`.
- The generic TCP handler path can use `TCP::Protocol` to detect HTTP, RDP, or MongoDB.
- HTTP payloads detected through the generic TCP path can be handled by `protocols/spicy/handlers/http.go`.

A rule target of `http` calls the Go HTTP handler in `protocols/tcp/http.go`; it does not auto-select the Spicy HTTP handler.

## Producer responsibilities

Handlers choose what to pass to producers. The envelope is fixed (`producer.Event`); the `decoded` payload is handler-specific. When adding a handler, decide what raw payload to include, what decoded structure is stable enough for downstream consumers, whether public addresses need sanitization, and what protocol name to pass to `ProduceTCP(...)` / `ProduceUDP(...)`.

## Tests

For a new handler or parser:

- handler registration test in `protocols/protocols_test.go` when adding map keys
- handler behavior tests beside the handler package
- parser tests under `protocols/spicy/` for Spicy field contracts
- rules tests under `rules/` when rule behavior changes

Cover both successful and malformed input.
