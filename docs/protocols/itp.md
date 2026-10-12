# `itp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `layout`, `sequence`, `last_sequence`, `sequence_status`, `pactyp`, `version`, `surgeon_mode`, `checksum`, `checksum_ok`, `button_state`, `grasp`, `packets`, `runlevel`, `payload`, `truncated`

Interoperable Teleoperation Protocol (udp/36000), the link between a telesurgery master console and a slave robot (2009 ITP Plugfest; UW BioRobotics Raven II `itp_teleoperation.h`). The honeypot plays the slave robot. Packets are little-endian packed C structs with no header, so a datagram is recognised only by its size:

| Struct | Size | Layout |
| --- | --- | --- |
| `u_struct` v0.43 (master → slave) | 84 | `sequence pactyp version` (u32), `delx dely delz delyaw delpitch delroll` (2×i32 each), `buttonstate[2] grasp[2] surgeon_mode checksum` (i32) |
| `u_struct` Raven II | 124 | as v0.43, but orientation is `Qx Qy Qz Qw` (2×float64 each) |
| `v_struct` (slave → master) | 52 | `sequence last_sequence pactyp version` (u32), `fx fy fz` (2×i32 each), `runlevel` (i32), `jointflags` (u32), `checksum` (i32) |

Read frames: `command` is `u_struct` (or `UNKNOWN` for any other size, which gets no reply); `layout` is `v0.43` or `raven2`. `checksum_ok` compares `checksum` with the Raven II `UDPChecksum` (`surgeon_mode` + position increments + buttons + `sequence`); Raven computes it but does not drop bad packets. `sequence_status` follows the Raven II network layer, tracked per source IP and port: `new` (first packet), `valid` (last+1), `skipped`, `duplicate`, `reset` (more than 1000 behind), `out_of_sequence`, or `reflect` (sequence 0). A stream expires after 5 s of silence (`MASTER_CONN_TIMEOUT`) and the table holds at most 1024 streams (the oldest is evicted). `packets` is the datagram count of the stream.

Write frames: sequence 0 is reflected back unchanged (`command`/`status` `reflect`). Otherwise the reply is a `v_struct` (`command` `v_struct`) echoing the master's `pactyp`/`version`, with the slave's own `sequence`, `last_sequence` set to the master's sequence, zero force feedback and joint flags, and `runlevel` `PEDAL_DN` while `surgeon_mode` is 1, else `PEDAL_UP` (also in `status`). The reply `checksum` is `runlevel` + forces + `sequence` (Raven leaves it unset). Replies are never larger than the request and go through the UDP reply budget.

Not emulated: motion or kinematics, force feedback, E-STOP/INIT transitions, and Secure ITP (no public wire spec).
