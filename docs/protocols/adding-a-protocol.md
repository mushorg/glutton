# Adding a protocol

End-to-end source changes to add a new protocol path. Start with a Go handler. Add a Spicy parser only when byte-level field extraction is useful and you're ready to wire that parser into live traffic.

## 1. Pick the shape

| Shape | Use when |
| --- | --- |
| Go handler only | Simple interaction, banner capture, response shaping, or payload logging. |
| Go handler + Spicy parser | You need structured parsing but Go still owns responses and producer events. |
| Spicy detection from generic TCP | You want catch-all TCP traffic classified before fallback handling. |

A `.spicy` file alone does nothing — a compiled parser must be called from Go or routed through handler logic.

## 2. Add a TCP handler

Create `protocols/tcp/example.go`:

```go
package tcp

import (
	"context"
	"fmt"
	"net"

	"github.com/mushorg/glutton/connection"
	"github.com/mushorg/glutton/protocols/interfaces"
)

type decodedExample struct {
	Greeting string `json:"greeting,omitempty"`
}

func HandleExample(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
	defer conn.Close()

	if err := h.UpdateConnectionTimeout(ctx, conn); err != nil {
		return err
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read example payload: %w", err)
	}
	payload := buf[:n]

	logger.Info("example protocol request handled")

	if err := h.ProduceTCP("example", conn, md, payload, decodedExample{Greeting: string(payload)}); err != nil {
		logger.Error("failed to produce example event", "error", err)
	}

	_, err = conn.Write([]byte("OK\r\n"))
	return err
}
```

Style references in-tree: `protocols/tcp/http.go`, `protocols/tcp/tcp.go`, `protocols/tcp/mongodb.go` cover different interaction depths and decoded shapes.

## 3. Register the handler

In `protocols/protocols.go`, add to `MapTCPProtocolHandlers(...)`:

```go
protocolHandlers["example"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
	return tcp.HandleExample(ctx, conn, md, log, h)
}
```

UDP handlers register through `MapUDPProtocolHandlers(...)` instead.

## 4. Add a rule

In `config/rules.yaml`:

```yaml
rules:
  - match: tcp dst port 9999
    type: conn_handler
    target: example
```

Place specific rules before broad catch-alls like `match: tcp`.

## 5. Add tests

- registration assertion in `protocols/protocols_test.go`
- handler behavior tests beside the handler
- malformed input / short read coverage
- producer call coverage when the handler emits decoded data

Use the mock honeypot in `protocols/mocks/` for producer assertions.

## 6. Optional: add a Spicy parser

Add a grammar under `protocols/spicy/parsers/`. Existing examples: `http.spicy`, `tcp.spicy`.

```bash
export PATH=/opt/spicy/bin:$PATH
make spicy
```

The Spicy Makefile generates gitignored C++ and headers under `protocols/spicy/`. Parser registration happens at runtime in `spicy.Initialize(...)`: names like `HTTP::Request` are split on `::`, lowercased by module name, and registered as parser key `http`.

Call from Go:

```go
parsed, err := spicy.Parse("example", payload)
if err != nil {
	return err
}
```

Consume `parsed.Fields` in the handler. Do not move connection lifecycle, logging, producer calls, or fake responses into Spicy.

## 7. Optional: detect from the generic TCP path

The generic `tcp` target peeks at initial bytes and, when Spicy is enabled, calls the `tcp` parser to classify HTTP, RDP, or MongoDB payloads. To add a detector:

1. extend `protocols/spicy/parsers/tcp.spicy`
2. regenerate parser artifacts with `make spicy`
3. update the switch in `protocols/protocols.go`
4. add parser and routing tests

Only do this for protocols that should be detected from catch-all TCP. If the protocol has a stable port, a dedicated rule is simpler.

## 8. Verify

```bash
export PATH=/opt/spicy/bin:$PATH
CC=clang CXX=clang++ go test ./...
```

For faster iteration during development, scope to the package: `go test ./protocols/...`.
