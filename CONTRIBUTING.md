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
  - Handler registration or protocol behavior → [Architecture](docs/architecture.md), [Extension system](docs/extension-system.md), [FAQ](docs/faq.md), the handler key list in [Configuration](docs/configuration.md), and the protocol's page under [docs/protocols/](docs/protocols/)
  - Producer event fields → [Logging and producers](docs/logging.md)
  - Spicy parser coverage → [Spicy cheatsheet](docs/protocols/spicy-cheatsheet.md)

## Code style and PRs

- **Format:** run `gofmt` and mirror the structure of existing handlers in `protocols/tcp/` and `protocols/udp/`. [AGENTS.md](AGENTS.md) describes the canonical handler shape.
- **Respect the boundary:** byte-level parsing and response building belong in a Go sub-package (e.g. `protocols/tcp/smb/`) or a `.spicy` grammar; connection lifecycle, logging, producer calls, and fake responses stay in the Go handler. Never commit generated Spicy artifacts — they're git-ignored.
- **Test before pushing:** run `go test ./protocols/... ./rules/...` while iterating, and the full `CC=clang-17 CXX=clang++-17 go test ./...` (Spicy must be installed) before opening a PR. If you changed any `.spicy` file, run `make spicy` first so tests pick up the regenerated parser.
- **Write a focused PR:** describe what changed, how you tested it, and which docs moved with it. Keep unrelated cleanup in its own PR.

## AI agents

AI coding agents (Claude Code, Copilot, Cursor, Codex, and similar) are welcome, but their use **must be disclosed**.

- **Disclose in the PR description** which tool you used and for what (e.g. "handler and tests drafted with Claude Code, reviewed and edited by hand"). Commits written largely by an agent should also carry a `Co-Authored-By:` trailer naming it. Issues and review comments drafted by an agent need the same note.
- **You own the change.** Read every line before you open the PR, run the tests yourself, and be ready to explain and defend it in review. Undisclosed or unreviewed agent output may be closed without review.
- **Verify against the source.** Agents invent field names, opcodes, and RFC details. Check protocol behavior against the spec or captured traffic, and the producer event shape against [Logging and producers](docs/logging.md).
- **Point your agent at [AGENTS.md](AGENTS.md).** It describes the handler skeleton, rules, and checklist agents should follow in this repo.
- **Keep secrets and private data out of prompts.** Don't paste credentials, real attacker IPs beyond what an issue already shows, or non-public captures into third-party tools.
