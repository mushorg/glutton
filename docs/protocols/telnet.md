# `telnet` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

`decoded` is an array of per-direction frames, one event per TCP session.

## Fields

| Field | Set on | Meaning |
| --- | --- | --- |
| `direction` | all | `read` (from attacker) or `write` (from honeypot). |
| `command` | reads | `username` / `password` on login reads; otherwise the first token of the shell line, cut at whitespace or a shell operator (`ping; sh` → `ping`). `tls_client_hello` or `binary` for non-telnet input. Login prompt writes also set `username` / `password`. |
| `message` | all | Line as sent or written, CRLF and NUL terminators included. Credentials are recorded as sent. On a merged echo-loader frame (`lines` > 1) it holds every merged line, raw and in order. |
| `path` | `wget` / `curl` reads; echo-loader reads; `chmod` / `./F` / `sh F` reads | The http(s) URL from the command line; the file an `echo -e … > F` / `>> F` line writes; the first echo-built file a line makes executable or runs. |
| `lines` | echo-loader reads | Number of `echo -e … >> F` lines merged into this frame (1 for an unmerged one). |
| `commands` | shell reads of a chained line | First word of every `;`, `&&`, `\|\|` or `\|` separated command (at most 32), only set when the line has more than one. `command` keeps the first word, so a probe after it (e.g. `/bin/busybox HISILICON` after `cd /root/;`) stays queryable. |
| `payload_hash` | `wget` / `curl` reads; `chmod` / `./F` / `sh F` reads; echo-loader reads | SHA-256 of the fetched sample, set when the fetch succeeds; of the echo-built file a line runs; or, for a file never run, of its final content on its last echo frame. |
| `offset_ms` | all | Milliseconds since the connection was accepted (omitted when 0). Shows how long a bot waits between a write and its next command. |
| `truncated` | reads | The line was longer than 64 KiB and `message` holds its first 64 KiB (the rest is dropped; the next line is read normally), or this is the last read kept when the session hit its frame limit, or (echo-loader reads) the file hit its 1 MiB cap or the connection its 4 MiB total and later bytes were dropped. |
| `variant` / `visit` | ELF header writes | Architecture of the visit (`arm`, `mips`, `mipsel`) and the source's visit number. Empty on all other frames. |

## Behaviour

**Login.** The honeypot sends IAC negotiation, then `Username: ` and `Password: `. Any credentials are accepted and answered with `welcome\r\n> `. IAC bytes the client sends are recorded as a separate `read` frame with no `command`, so credential frames stay clean.

**Non-telnet input.** If the first client bytes are binary (not IAC or text), the login flow is skipped and one `read` frame is recorded with `command` `tls_client_hello` (`0x16 0x03` prefix) or `binary`. The rule uses `tls: auto`, so real TLS hellos are normally terminated before the handler.

**Shell.** Each line is split on `;`. Each part is matched against canned Mirai/Hajime replies after trimming whitespace and NUL terminators, with or without a `/bin/busybox ` prefix. For `a || b`, the first alternative with a canned reply wins. Each line ends with the prompt `> `. `enable`, `linuxshell`, `system`, `shell`, and `sh` are silent (only `> `): a `-bash: X: command not found` body contains `:`, which Mirai's `consume_any_prompt` treats as a prompt, and any distinct `sh` write (`$ `, `~ # `, `\r\n> `) stalled this fleet after it had answered every bare `> ` (Ochi event 1997a98e). Do not print `MIRAI: applet not found` on `sh`; that string is BusyBox's reply to `/bin/busybox MIRAI` only. A bare `/bin/busybox` prints the BusyBox multi-call usage and applet list; a bare `ping` prints its usage line. The dated ash banner is still written after `/bin/busybox <unknown>` applet replies.

**BusyBox applets.** `/bin/busybox <TOKEN>` gets `<TOKEN>: applet not found` plus the ash banner only when `<TOKEN>` is not a known applet (Mirai's BusyBox liveness check). `cat` of an unknown file gets `cat: <file>: No such file or directory`.

**CPU info.** `cat /proc/cpuinfo` (also `/bin/busybox cat /proc/cpuinfo`, and `a || b` chains resolve to the first alternative) prints a per-architecture `/proc/cpuinfo` matching the visit's ELF persona: ARMv7 / `Hardware : hi3516dv100` for `arm`, a HiSilicon `Hi3520` MIPS 24Kc for `mips` and `mipsel`. The write frame carries `variant` and `visit` like the ELF replies. Older sensors (up to v1.0.1+a14c3ee) answered with `cat: /proc/cpuinfo: No such file or directory`, which contradicted the `/proc/mounts` reply and ended the session (Ochi event d8d09e26-2661-4a60-af43-8a659d368918).

**Architecture probes.** These commands all print the same 52-byte ELF32 header of the fake BusyBox static executable, which Mirai reads to pick its loader:

- `cat /proc/self/exe`
- `cat /bin/busybox`
- `cat /bin/sh`
- `/bin/busybox cat /bin/echo`
- `dd bs=52 count=1 if=.s`

**Sample downloads.** `wget` / `curl` lines with an http(s) URL set `path`; the sample is fetched in the background (up to 10 MiB), stored under `samples/`, and its SHA-256 set as `payload_hash`. At most 8 downloads run per connection and 32 across the sensor at once; a `wget` / `curl` beyond either limit keeps its `path` but is not fetched, so it has no `payload_hash`.

**Echo-loader files.** Mirai writes its downloader 32 bytes per line (`/bin/busybox echo -ne "\x7f\x45…" > .d`, then `>> .d`) and runs it with `chmod +x .d; ./.d`. The handler rebuilds every file written by an escape-interpreting `echo` (`-e`, `-ne`, `-en`) on a single-command line: `>` truncates, `>>` appends, extra words are joined with spaces as echo does (`"…"  ar >> .k` appends ` ar`), and BusyBox escapes (`\xHH`, `\0NNN`, `\n`, `\c`, …) are decoded. Files are keyed by the name as sent, without a leading `./`, and capped at 1 MiB each and 4 MiB per connection. A line that runs or makes executable such a file (`chmod … F`, `./F`, `sh F`, with or without `/bin/busybox`) stores the file's current content under `samples/` and sets `path` and `payload_hash` on that read frame; files never run are stored at session end and the hash goes on their last echo frame. Each distinct content is stored once per connection. Nothing is executed. Consecutive `>>` appends to the same file are merged into the read frame of the first line (`lines` counts them, `message` holds all of them) and their `> ` prompts are sent but not recorded, so a loader for eight architectures (~420 lines) costs a handful of frames instead of ~840. A merged frame holds at most 256 KiB of lines; the next line starts a new frame. Sensors before this change recorded one read and one `> ` write per line, stored nothing, and an 8-architecture loader hit the frame limit (Ochi event bedf4355-6886-489c-b2f6-69df475a314c).

**Session limit.** A connection keeps at most about 1000 frames; then the event is produced with `endReason` `max_frames`.

## Returning sources

The visit's variant picks the ELF header's architecture, the post-login greeting, and how unknown commands are reported. A visit is all telnet traffic from one source IP with no gap longer than `recall.visit_gap` (default 30 min). Each new visit moves to the next variant, so a returning Mirai bot downloads a different loader or binary:

| Variant | Visits | Header | Greeting | Other `-bash:` errors (before `sh`) |
| --- | --- | --- | --- | --- |
| `arm` | 1, 4, … | little-endian, `e_machine` 0x28, EABI5 | `welcome` | `-bash: X: command not found` |
| `mips` | 2, 5, … | big-endian, `e_machine` 0x08, o32 | `Welcome` | `-sh: X: command not found` |
| `mipsel` | 3, 6, … | little-endian, `e_machine` 0x08, o32 | `Welcome!` | `sh: X: not found` |

Write frames that depend on the variant set `variant` and `visit`: ELF headers, and (for `mips`/`mipsel`) the greeting and restyled not-found replies. `arm` is the original persona, so its greeting and errors carry no tag. Inside `sh` every variant uses the ash `sh: X: not found` form.

## Process logs

- Info `telnet login` with `src_ip`, `src_port`, `dest_port`, `username`, `password`. Not logged for non-telnet input.
- Info `returning telnet source` with `visit`, `variant`, `previous_variant`, `previous_commands`.
- Info `New sample fetched` with `sample_hash` and `source`.
- Info `New sample rebuilt from echo` with `sample_hash`, `path`, `bytes`, `truncated`.
- Shell lines at Debug.
