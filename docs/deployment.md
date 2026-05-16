# Deployment

Last verified against source on 2026-05-15.

Glutton is intended to run as an isolated Linux sensor. Treat it as hostile-facing infrastructure: it receives unsolicited traffic, records attacker-controlled payloads, and installs network redirection rules.

## Runtime Model

At runtime Glutton:

1. reads config from `--confpath`
2. reads rules from `rules_path`
3. starts TCP and UDP TPROXY listeners on `127.0.0.1`
4. appends mangle table PREROUTING rules with `TPROXY --on-ip 127.0.0.1`
5. dispatches traffic to handlers
6. writes JSON logs and optional producer events

The configured `ports.tcp` and `ports.udp` values are local redirect ports, not the public service ports attackers connect to. Public service matching is controlled by rules such as `tcp dst port 23`.

## Host Placement

Recommended deployment posture:

- Run Glutton on a dedicated host, VM, or container runtime segment.
- Do not run it on a workstation or host with sensitive internal access.
- Restrict outbound access unless a handler or producer explicitly needs it.
- Rotate and export logs before disk pressure becomes operational risk.
- Keep producer endpoints separate from the exposed honeypot network.

Glutton is a sensor, not a containment boundary. Use network isolation around it.

## Privileges

Glutton needs permission to:

- read from TPROXY sockets
- add and remove iptables mangle table rules
- bind local TCP and UDP listener ports
- write its sensor ID under `--var-dir`
- write the configured log file

For bare-metal or VM deployment, this usually means running with root privileges. For Docker, the documented run path uses `--cap-add=NET_ADMIN`.

## Bare Binary

```bash
export PATH=/opt/spicy/bin:$PATH
make spicy
make build
sudo bin/server --interface eth0 --confpath config/ --logpath /var/log/glutton.log
```

Confirm that `--interface` is the interface receiving the traffic you want to observe. Glutton uses that interface both to discover public addresses and to build TPROXY rules.

## Docker

```bash
docker build -t glutton .
docker run --rm --cap-add=NET_ADMIN -it glutton
```

The Dockerfile copies `config/` into `/opt/glutton/config` and runs the server with interface `eth0`. If you mount custom config, keep `rules_path` valid inside the container.

## Configuration Files

The default run path expects:

```text
config/config.yaml
config/rules.yaml
```

If the configured `--confpath` directory exists but `config.yaml` cannot be read from it, startup fails. If the config directory itself does not exist, Glutton falls back to the embedded default config. If `rules_path` does not exist, Glutton falls back to the embedded default rules.

## SSH Exclusion

The iptables rules exclude one destination port through `! --dport <ports.ssh>`. This is intended to avoid redirecting the management SSH port into the honeypot. Set `ports.ssh` in config or pass `--ssh` explicitly for the host you are deploying.

There is a source-level default ambiguity: `config/config.yaml` sets `ports.ssh: 2222`, while the CLI flag registration uses `--ssh` default `22`. Do not rely on an implicit SSH exclusion value in production.

## Producers

The process JSON log is local. Producer output is optional and configured under `producers`. If `producers.enabled` is false, handlers can call `ProduceTCP` or `ProduceUDP`, but no producer event is sent.

HTTP producer output skips private source IP addresses. hpfeeds output connects to the configured broker and channel at startup.

## Operational Hazards

- iptables state can be left behind if the process is killed without normal shutdown.
- Captured payloads are attacker-controlled data. Handle them as untrusted.
- Some handlers intentionally send fake service responses. Do not route internal production clients through the sensor.
- `proxy_tcp` rules can create outbound connections from the sensor to configured upstream services. Restrict egress so proxy targets are explicit and expected.
- Legal and privacy obligations vary by deployment environment. Get local review before collecting or sharing traffic payloads.
