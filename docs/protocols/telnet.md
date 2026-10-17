# `telnet` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

`decoded` is an array of per-direction frames, one event per TCP session.

## Fields

| Field | Set on | Meaning |
| --- | --- | --- |
| `direction` | all | `read` (from attacker) or `write` (from honeypot). |
| `command` | reads | `username` / `password` on login reads; otherwise the first token of the shell line, cut at whitespace or a shell operator (`ping; sh` → `ping`). `tls_client_hello` or `binary` for non-telnet input. Login prompt writes also set `username` / `password`. |
| `message` | all | Line as sent or written, CRLF and NUL terminators included. Credentials are recorded as sent. |
| `path` | `wget` / `curl` reads | The http(s) URL from the command line. |
| `payload_hash` | `wget` / `curl` reads | SHA-256 of the fetched sample, set when the fetch succeeds. |
| `variant` / `visit` | ELF header writes | Architecture of the visit (`arm`, `mips`, `mipsel`) and the source's visit number. Empty on all other frames. |

## Behaviour

**Login.** The honeypot sends IAC negotiation, then `Username: ` and `Password: `. Any credentials are accepted and answered with `welcome\r\n> `. IAC bytes the client sends are recorded as a separate `read` frame with no `command`, so credential frames stay clean.

**Non-telnet input.** If the first client bytes are binary (not IAC or text), the login flow is skipped and one `read` frame is recorded with `command` `tls_client_hello` (`0x16 0x03` prefix) or `binary`. The rule uses `tls: auto`, so real TLS hellos are normally terminated before the handler.

**Shell.** Each line is split on `;`. Each part is matched against canned Mirai/Hajime replies after trimming whitespace and NUL terminators, with or without a `/bin/busybox ` prefix. For `a || b`, the first alternative with a canned reply wins. Before `sh` each line ends with the prompt `> `. `sh` writes the BusyBox ash banner (`BusyBox v1.16.1 ... built-in shell (ash)`, `Enter 'help' ...`) followed by the root prompt `~ # ` (no CRLF) in one write frame, and switches the session into that shell: from then on every line ends with `~ # `, and bash-style `-bash: X: command not found` replies become ash-style `sh: X: not found`. A bare `/bin/busybox` prints the BusyBox multi-call usage and applet list; a bare `ping` prints its usage line. The prompt sigil must not be the first byte: Mirai's `consume_any_prompt` never checks index 0 of its receive buffer, so the bare `$ ` that older sensors sent stalled the bot until it timed out.

**BusyBox applets.** `/bin/busybox <TOKEN>` gets `<TOKEN>: applet not found` plus the ash banner only when `<TOKEN>` is not a known applet (Mirai's BusyBox liveness check). `cat` of an unknown file gets `cat: <file>: No such file or directory`.

**Architecture probes.** These commands all print the same 52-byte ELF32 header of the fake BusyBox static executable, which Mirai reads to pick its loader:

- `cat /proc/self/exe`
- `cat /bin/busybox`
- `cat /bin/sh`
- `/bin/busybox cat /bin/echo`
- `dd bs=52 count=1 if=.s`

**Sample downloads.** `wget` / `curl` lines with an http(s) URL set `path`; the sample is fetched in the background (up to 10 MiB), stored under `samples/`, and its SHA-256 set as `payload_hash`.

## Returning sources

The visit's variant picks the ELF header's architecture, the post-login greeting, and how unknown commands are reported. A visit is all telnet traffic from one source IP with no gap longer than `recall.visit_gap` (default 30 min). Each new visit moves to the next variant, so a returning Mirai bot downloads a different loader or binary:

| Variant | Visits | Header | Greeting | Unknown command (before `sh`) |
| --- | --- | --- | --- | --- |
| `arm` | 1, 4, … | little-endian, `e_machine` 0x28, EABI5 | `welcome` | `-bash: X: command not found` |
| `mips` | 2, 5, … | big-endian, `e_machine` 0x08, o32 | `Welcome` | `-sh: X: command not found` |
| `mipsel` | 3, 6, … | little-endian, `e_machine` 0x08, o32 | `Welcome!` | `sh: X: not found` |

Write frames that depend on the variant set `variant` and `visit`: ELF headers, and (for `mips`/`mipsel`) the greeting and restyled not-found replies. `arm` is the original persona, so its greeting and errors carry no tag. Inside `sh` every variant uses the ash `sh: X: not found` form.

## Process logs

- Info `telnet login` with `src_ip`, `src_port`, `dest_port`, `username`, `password`. Not logged for non-telnet input.
- Info `returning telnet source` with `visit`, `variant`, `previous_variant`, `previous_commands`.
- Info `New sample fetched` with `sample_hash` and `source`.
- Shell lines at Debug.
