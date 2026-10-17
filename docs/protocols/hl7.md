# `hl7` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `control_id`, `version`, `sending_application`, `sending_facility`, `receiving_application`, `receiving_facility`, `security`, `segments`, `framing`, `status`, `payload`, `truncated`

HL7 v2 over MLLP (tcp/2575), the port hospital interface engines exchange ADT, ORM, ORU and query messages on. Messages are read as MLLP frames (`0x0B` … `0x1C 0x0D`) or, for senders that skip the framing, as whatever arrives in one chunk; `framing` says which (`mllp` or `raw`). `payload` keeps the wire bytes, framing included.

Reads set the MSH fields: `command` is the message type from MSH-9 (`ADT^A01`, `QRY^A19`), `control_id` MSH-10, `version` MSH-12, the sending/receiving application and facility MSH-3 to MSH-6, and `security` MSH-8 as the client sent it. `segments` lists the segment IDs in order (at most 100).

Every message gets an original-mode acknowledgement in the request's framing. The ACK swaps sender and receiver, echoes the separators, processing ID and version, and acknowledges the request's control ID in `MSA-2`. Writes set `command` (`ACK^A01`), the ACK's own `control_id`, and `status` to the MSA code:

| `status` | When |
| --- | --- |
| `AA` | The message starts with a usable MSH. |
| `AE` | MSH-9 or MSH-10 is missing; an `ERR` segment carries code 101. |
| `AR` | The message has no MSH; an `ERR` segment carries code 100. |

Queries (`QRY`, `QBP`) only get an ACK, never patient data. Messages over 1 MiB are stored up to the cap with `truncated` and the connection is closed. Non-HL7 traffic on the port goes through the `tcp` catch-all dispatch, which also routes HL7 seen on other ports (e.g. Mirth's 6661) to this handler.
