# Extension

Glutton is built to be easily extensible. Developers can add new protocol handlers or modify existing behavior to suit custom requirements.

## Adding a New Protocol Handler

### Create a New Module

   - Add your new protocol handler in the appropriate subdirectory under `protocols/` (e.g., `protocols/tcp` or `protocols/udp`).
   - Implement the handler function conforming to the expected signature:
     - For TCP: `func(context.Context, net.Conn, connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error`
     - For UDP: `func(context.Context, *net.UDPAddr, *net.UDPAddr, []byte, connection.Metadata) error`
   
   For example:


            // protocols/tcp/new_protocol.go

            package tcp

            import (
               "context"
               "net"
               
               "github.com/mushorg/glutton/connection"
               "github.com/mushorg/glutton/protocols/interfaces"
            )

            // HandleNewProtocol handles incoming connections.
            func HandleNewProtocol(ctx context.Context, conn net.Conn, md connection.Metadata, logger interfaces.Logger, h interfaces.Honeypot) error {
               // Log the connection for demonstration purposes.
               logger.Info("Received NewProtocol connection from %s", conn.RemoteAddr().String())
               // Here you could add protocol-specific handling logic.
               // For now, simply close the connection.
               return conn.Close()
            }


### Register the Handler
   - Modify the mapping function (e.g., `protocols.MapTCPProtocolHandlers` or `protocols.MapUDPProtocolHandlers` in `protocols/protocols.go`) to include your new handler.
   - Update configuration or rules (in `config/rules.yaml` or `rules/rules.yaml`) if needed to route specific traffic to your handler.

For example:

            func MapTCPProtocolHandlers(log interfaces.Logger, h interfaces.Honeypot) map[string]TCPHandlerFunc {
               protocolHandlers := map[string]TCPHandlerFunc{}
               protocolHandlers["smtp"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
                  return tcp.HandleSMTP(ctx, conn, md, log, h)
               }
               ...
               protocolHandlers["new"] = func(ctx context.Context, conn net.Conn, md connection.Metadata) error {
                  return tcp.HandleNewProtocol(ctx, conn, md, log, h)
               }
               ...
            }

3. **Test Your Extension:**
      - Write tests similar to those in `protocols/protocols_test.go` to verify your new handler’s functionality.
      - Use `go test` to ensure that your changes do not break existing functionality.

## Spicy Parser Integration

Glutton can use [Spicy](https://docs.zeek.org/projects/spicy/en/latest/) parsers when `spicy.enabled: true` is set in `config/config.yaml`. Spicy parsing is currently used for:

- HTTP request parsing through `HTTP::Request`, with Glutton behavior implemented in `protocols/spicy/handlers/http.go`.
- TCP payload protocol detection through `TCP::Protocol`, which helps route raw TCP traffic to HTTP, RDP, MongoDB, or the fallback TCP handler.

Spicy does not replace Glutton's handler layer. The parser extracts structured fields from bytes; Go handlers still own connection handling, logging, producer events, responses, and fallback behavior.

### Architecture

The Spicy integration has three main parts:

- **C++ bridge:** `protocols/spicy/bridge.{h,cpp}` initializes and shuts down the Spicy/HILTI runtime, exposes the generic `spicy_parse_generic()` entry point, lists compiled parsers, and flattens parsed HILTI values into key-value fields.
- **Generated parser code:** `make spicy` compiles `protocols/spicy/parsers/*.spicy` into generated C++ files and creates the combined Spicy linker file used to register parser modules.
- **Go parser worker:** `protocols/spicy/parser.go` runs Spicy calls on a dedicated OS thread with `runtime.LockOSThread()`, communicates through a command channel, keeps the parser registry, and applies timeout protection around parsing.

The bridge is intentionally protocol-agnostic. New parsers should not add parser-specific includes or parser-specific logic to `bridge.cpp`; concrete parser modules are registered through the generated linker code.

### Parsed Field Shape

The bridge recursively flattens Spicy/HILTI values into a flat map:

- Struct fields become `field` or `parent.field`.
- Vectors and arrays become `field[0]`, `field[1]`, and so on.
- Maps become `field.key`.
- Nested values are depth-limited to prevent runaway recursion.

For example, an HTTP parser can expose fields such as `method`, `path`, `query`, `version.number`, or `headers[0].name`.

### TCP Protocol Detection

When Spicy is enabled, the raw TCP dispatcher can call `spicy.Parse("tcp", sample)` before falling back to the older byte-prefix checks. The `TCP::Protocol` parser inspects application payload bytes, not TCP/IP headers.

The detector currently recognizes:

- HTTP from the first request bytes.
- RDP from the initial connection bytes.
- MongoDB from a valid 16-byte message header.

Unknown or invalid samples continue through the normal fallback TCP handler.

### Adding a Spicy Parser

1. Add a grammar under `protocols/spicy/parsers/*.spicy`.
2. Run `make spicy` before building or testing so generated parser C++ files, parser headers, and the combined linker file are available.
3. Use the parser from Go through `spicy.Parse("<protocol>", payload)`. Parser names are registered from compiled Spicy module names, for example `HTTP::Request` is available as `http`.
4. Add or update Glutton routing and handler code when the parser should be used for live traffic. A compiled grammar makes parsing available, but it does not decide how much data to read, what handler to call, what response to send, or which producer event shape to emit.
5. Add tests for the parser and any handler or routing behavior that consumes it.

## Customizing Logging and Rules

- **Logging:** The logging mechanism is provided by the Producer (located in `producer/`). You can modify or extend it to suit your logging infrastructure.
- **Rules Engine:** The rules engine (found in `rules/`) can be extended to support additional matching criteria or custom rule types.
