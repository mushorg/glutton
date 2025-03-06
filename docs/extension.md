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

## Customizing Logging and Rules

- **Logging:** The logging mechanism is provided by the Producer (located in `producer/`). You can modify or extend it to suit your logging infrastructure.
- **Rules Engine:** The rules engine (found in `rules/`) can be extended to support additional matching criteria or custom rule types.

