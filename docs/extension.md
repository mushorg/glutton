# Extension

Last verified against source on 2026-05-15.

This page is kept for existing documentation links. The extension documentation has been split into focused pages:

- [Extension system](extension-system.md) explains the extension model and the boundary between rules, Go handlers, Spicy parsers, logs, and producers.
- [Adding a protocol](protocols/adding-a-protocol.md) walks through the source files that need to change when adding a handler or parser.
- [Spicy cheatsheet](protocols/spicy-cheatsheet.md) covers the minimum Spicy concepts needed in this repository.

The short version: Glutton extensions usually involve a rule target, a Go handler, handler registration in `protocols/protocols.go`, tests, and optionally a Spicy parser under `protocols/spicy/parsers/`. A compiled `.spicy` file alone does not make live traffic use that parser.
