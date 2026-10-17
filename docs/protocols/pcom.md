# `pcom` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `mode`, `tid`, `unit`, `command`, `status`, `payload`, `truncated`

Unitronics PCOM over TCP (tcp/20256, Vision/Samba PLCs). The framing and both checksums are checked against two captured scans (Ochi events `e5e87010-e004-4784-977d-5b6afc6fddd8` and `db359b9c-00ad-4914-adfc-c15a8d34922a`); the ID reply and the error reply are **not** captured and are a guess, not the vendor spec.

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 2 | LE transaction id (the captures used ASCII pairs such as `SI`, `IU`, `WI`) |
| 2 | 1 | mode: `0x65` ASCII, `0x66` binary |
| 3 | 1 | reserved (0) |
| 4 | 2 | LE length of the message |
| 6 | rest | PCOM message |

- **ASCII message:** `/` unit(2 chars) command(2 chars) data checksum(2 hex) `\r`. The checksum is the sum of the bytes after `/` modulo 256 (verified on the captured `ID`, `UG` and `RN` requests; unit `40` in one capture, `" 1"` in the other). `unit`, `command` (`ID`, `UG`, `RN`, ...) are recorded as parsed. A bad checksum is not rejected.
- **Binary message:** starts `/_OPLC`, ends `\` (`0x5c`). Bytes 22-23 are a little-endian header checksum (two's complement of the sum of bytes 0-21), verified on the capture; bytes 20-21 are the data length and the footer checksum is the same function over the data. `unit` is byte 6 (decimal) and `command` is byte 12 as `0x0c`; those two offsets are a guess.
- **Replies are synthetic.** The transaction id and mode are echoed. An ASCII `ID` gets `/A` unit `ID` model code(6) hardware(1) OS major/minor/build(2 digits each) checksum (`status` `id`; the model code is fixed, the build number is random per process). Every other ASCII command, and an ASCII body that does not parse, gets `/E` unit `01` checksum (`status` `error`). A binary message gets its header echoed with no data and valid checksums (`status` `echo`); one that does not parse gets no reply. The handler never writes to a PLC.
- A header with an unknown mode byte, a non-zero reserved byte, a zero length or a length above 4 KiB ends the session (`endReason` `read_error`); the bytes read are kept as a read frame (`truncated` for an oversize length). A session holds at most 64 frames (`endReason` `max_frames`).

tcp/20256 is routed here by rule; there is no generic-peek routing for other ports.
