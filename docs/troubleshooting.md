# Troubleshooting

Last verified against source on 2026-05-15.

## `spicyc: command not found`

`make spicy` requires the Spicy CLI on PATH.

```bash
export PATH=/opt/spicy/bin:$PATH
make spicy
```

Install Spicy/HILTI first if `/opt/spicy/bin/spicyc` does not exist.

## Missing `spicy/rt/libspicy.h` Or `hilti/rt/libhilti.h`

The cgo flags in `protocols/spicy/parser.go` expect Spicy headers under:

```text
/opt/spicy/include
```

Install Spicy to `/opt/spicy` or update the build environment deliberately.

## Linker Cannot Find `-lspicy-rt` Or `-lhilti-rt`

The cgo linker flags expect libraries under:

```text
/opt/spicy/lib
```

Confirm the libraries exist and that your runtime linker can find them. The current cgo flags include an rpath for `/opt/spicy/lib`.

## Parser Not Found

If `spicy.Parse("http", payload)` returns `no Spicy parser registered`, check that:

1. `make spicy` ran successfully
2. generated parser artifacts exist in `protocols/spicy/`
3. the binary was rebuilt after generation
4. `spicy.enabled` is true
5. the module name matches the parser key you call from Go

Parser key registration uses the lowercased module name before `::`.

## `libpcap` Build Errors

Install libpcap development headers:

```bash
sudo apt-get install -y libpcap-dev
```

Other distributions use package names such as `libpcap-devel`.

## iptables Permission Errors

Glutton appends and deletes mangle table PREROUTING rules. Run with root or the capabilities required to manage iptables.

For Docker:

```bash
docker run --rm --cap-add=NET_ADMIN -it glutton
```

## No Traffic Reaches Handlers

Check:

- `--interface` matches the traffic-facing interface
- the host has a non-loopback IP on that interface
- `ports.ssh` is not excluding the traffic you expect to capture
- rules are ordered from specific to broad
- the rule target exists in `protocols/protocols.go`
- a broad `match: tcp` rule is not shadowing later rules

## `type: drop` Does Not Drop

The rules parser accepts `type: drop`, but the current listener paths do not special-case the Drop rule type after matching. Do not rely on it as a firewall action without adding explicit support or testing the exact path.

## Debug Logs Do Not Appear

`--debug` is parsed and bound through Viper, but the current logger setup does not use it to set a debug slog level. The JSON handler uses default slog handler options.

## Docker Build Problems

The current Dockerfile builds the server in an Alpine Go image. The Go package imports the Spicy cgo bridge, so the image build environment needs to stay aligned with the Spicy requirements used in CI. If Docker build fails on Spicy headers or libraries, update the Docker build environment to install Spicy/HILTI before `make build`.
