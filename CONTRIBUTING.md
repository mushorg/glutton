# Contributing To Glutton

Thanks for considering a contribution. Glutton is a security tool, so small source-verified changes are easier to review than broad rewrites.

## Development Setup

Use a Linux environment with the same dependency shape as CI:

```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev iptables zlib1g-dev build-essential clang
```

Install Spicy/HILTI under `/opt/spicy` and add its CLI to PATH:

```bash
export PATH=/opt/spicy/bin:$PATH
```

Then build:

```bash
make spicy
make build
```

## Tests

Run focused tests first:

```bash
go test ./protocols/...
go test ./rules/...
```

Run the full suite before opening a PR when the environment has Spicy installed:

```bash
CC=clang CXX=clang++ go test ./...
```

If you change `.spicy` files, run `make spicy` before testing.

## Code Style

- Run `gofmt` on Go files.
- Keep handler behavior close to existing patterns in `protocols/tcp/` and `protocols/udp/`.
- Keep Spicy parser behavior separate from Go handler behavior.
- Add tests beside the package you change.
- Do not commit generated Spicy artifacts. They are ignored by Git.

## Adding A Protocol

Read:

- [Extension system](docs/extension-system.md)
- [Adding a protocol](docs/protocols/adding-a-protocol.md)
- [Spicy cheatsheet](docs/protocols/spicy-cheatsheet.md)

Protocol changes usually need:

- a handler
- handler registration
- a rule example
- tests
- docs updates
- optional Spicy parser work

## Documentation Drift Checklist

When changing behavior, update docs in the same PR:

- CLI flags: update [Setup](docs/setup.md) and [Configuration](docs/configuration.md).
- Config defaults: update [Configuration](docs/configuration.md).
- Rules behavior: update [Rules engine](docs/rules-engine.md).
- Handler registration or protocol behavior: update [Architecture](docs/architecture.md), [Extension system](docs/extension-system.md), and [FAQ](docs/faq.md).
- Producer event fields: update [Logging and producers](docs/logging.md).
- Spicy parser coverage: update [Spicy cheatsheet](docs/protocols/spicy-cheatsheet.md).
- Build, CI, Docker, or Go version changes: update [Setup](docs/setup.md) and [Deployment](docs/deployment.md).

If source and docs disagree, the source is the authority unless the maintainer says the code is the bug.

## Pull Request Notes

In your PR description, include:

- what changed
- how it was tested
- any docs updated
- any source/doc drift you found but did not fix

Keep unrelated refactors out of functional PRs.
