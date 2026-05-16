# Contributing to Glutton

Thanks for considering a contribution. Glutton is a security tool, so small source-verified changes are easier to review than broad rewrites.

See [Getting started](docs/setup.md) for the toolchain, Spicy/HILTI, and Glutton build steps.

## Guidelines

- **Pick an issue** from the [tracker](https://github.com/mushorg/glutton/issues). Useful labels: `good first issue`, `help wanted`, `protocol`, `enhancement`. Reproduce older issues against `main` before starting. For protocol work, read [Extension system](docs/extension-system.md), [Adding a protocol](docs/protocols/adding-a-protocol.md), and [Spicy cheatsheet](docs/protocols/spicy-cheatsheet.md) first to gauge effort.
- **Comment before you start** so a maintainer can confirm scope or redirect.
- **Keep PRs small and source-verified.** Split large work into a thin first slice.
- **Add tests** beside the package you change.
- **Update docs in the same PR** when behavior changes:
  - Build/CI/Docker or Go version → [Getting started](docs/setup.md)
  - Config defaults or rules behavior → [Configuration](docs/configuration.md)
  - Handler registration or protocol behavior → [Architecture](docs/architecture.md), [Extension system](docs/extension-system.md), [FAQ](docs/faq.md)
  - Producer event fields → [Logging and producers](docs/logging.md)
  - Spicy parser coverage → [Spicy cheatsheet](docs/protocols/spicy-cheatsheet.md)

## Code style and PRs

- **Format** Mirror the structure of existing handlers in `protocols/tcp/` and `protocols/udp/`.
- **Respect the boundary:** parsing belongs in `.spicy` files, protocol logic in Go. Never commit generated parser artifacts — they're git-ignored.
- **Test before pushing:** run `go test ./protocols/... ./rules/...` while iterating, and the full `CC=clang CXX=clang++ go test ./...` (Spicy must be installed) before opening a PR. If you changed any `.spicy` file, run `make spicy` first so tests pick up the regenerated parser.
- **Write a focused PR:** describe what changed, how you tested it, and which docs moved with it. Keep unrelated cleanup in its own PR.