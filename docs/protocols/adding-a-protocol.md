# Adding A Protocol

Last verified against source on 2026-05-15.

This guide describes the source changes required to add a new protocol path. Start with a Go handler. Add a Spicy parser only when byte-level field extraction is useful and you are ready to wire that parser into live traffic.

## 1. Pick The Extension Shape

There are three common shapes:

| Shape | Use when |
| --- | --- |
| Go handler only | You need simple interaction, banner capture, protocol response shaping, or payload logging. |
| Go handler plus Spicy parser | You need structured parsing but Go still owns responses and producer events. |
| Spicy detection from generic TCP | You want catch-all TCP traffic to be classified before fallback handling. |

Do not add a `.spicy` file and assume Glutton will use it automatically. A compiled parser must be called from Go or routed through handler logic.

## 2. Add A TCP Handler

Create a file under `protocols/tcp/`, for example `protocols/tcp/example.go`:

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

Use existing handlers as the real style reference. `protocols/tcp/http.go`, `protocols/tcp/tcp.go`, and `protocols/tcp/mongodb.go` show different levels of interaction and decoded output.

## 3. Register The Handler

Add a key to `MapTCPProtocolHandlers(...)` in `protocols/protocols.go`:

```go
protocolHandlers["example"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
	return tcp.HandleExample(ctx, conn, md, log, h)
}
```

For UDP, add the handler to `MapUDPProtocolHandlers(...)` instead.

## 4. Add A Rule

Route a public destination port to the new handler in `config/rules.yaml`:

```yaml
rules:
  - match: tcp dst port 9999
    type: conn_handler
    target: example
```

Place specific rules before broad catch-all rules such as `match: tcp`.

## 5. Add Tests

At minimum:

- add a registration assertion in `protocols/protocols_test.go`
- add handler behavior tests beside the handler
- test malformed input or short reads
- test producer calls when the handler emits decoded data

Use the existing mock honeypot in `protocols/mocks/` when testing producer calls.

## 6. Optional: Add A Spicy Parser

Add a parser under `protocols/spicy/parsers/`. Existing real examples are:

```text
protocols/spicy/parsers/http.spicy
protocols/spicy/parsers/tcp.spicy
```

Run:

```bash
export PATH=/opt/spicy/bin:$PATH
make spicy
```

The Spicy Makefile generates ignored C++ and header artifacts under `protocols/spicy/`. Parser registration happens at runtime in `spicy.Initialize(...)`: names such as `HTTP::Request` are split on `::`, lowercased by module name, and registered as parser key `http`.

## 7. Call The Parser From Go

Use the Spicy API from Go:

```go
parsed, err := spicy.Parse("example", payload)
if err != nil {
	return err
}
```

Then consume `parsed.Fields` in the handler. Do not move connection lifecycle, logging, producer calls, or fake response behavior into Spicy.

## 8. Optional: Add Detection To The Generic TCP Path

The generic `tcp` target currently peeks at initial bytes and, when Spicy is enabled, calls the `tcp` parser to detect HTTP, RDP, and MongoDB. To add another detector:

1. extend `protocols/spicy/parsers/tcp.spicy`
2. regenerate parser artifacts with `make spicy`
3. update the switch in `protocols/protocols.go`
4. add parser and routing tests

Only do this for protocols that should be detected from the catch-all TCP path. If the protocol has a stable port, a rule target may be simpler and clearer.

## 9. Verify

Run the relevant tests first:

```bash
go test ./protocols/...
```

If the change touches Spicy:

```bash
export PATH=/opt/spicy/bin:$PATH
make spicy
CC=clang CXX=clang++ go test ./protocols/spicy/...
```

Then run the full suite in an environment with Spicy installed:

```bash
CC=clang CXX=clang++ go test ./...
```
