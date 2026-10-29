# `nbns` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `txid`, `status`, `payload`, `truncated`

udp/137. `command` is `NBSTAT` (qtype 0x21), `NB` (qtype 0x20), `REGISTRATION`, `RELEASE`, or `UNKNOWN`. `path` is the decoded NetBIOS name and suffix, e.g. `*<00>` or `SERVER<20>`.

An NBSTAT for `*` or `SERVER`, and an NB query for `SERVER`, get a reply (`status` repeats the command). The node-status table is `SERVER<00>`, `SERVER<20>` and group `WORKGROUP<00>`, the same server name the SMB handler advertises, plus a locally administered MAC derived from the destination address. An NB query for `SERVER` answers with the destination address. Registrations, releases, response packets, queries for any other name, and packets addressed to 255.255.255.255 or a multicast address are recorded with no reply. Scanners set the NBNS broadcast flag on unicast NBSTAT queries; those are still answered, unicast, through the UDP reply budget. Datagrams over 512 bytes are capped with `truncated`.
