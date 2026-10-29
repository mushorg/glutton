# `l2tp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `message_type`, `message_name`, `host_name`, `vendor_name`, `tunnel_id`, `session_id`, `assigned_tunnel_id`, `assigned_session_id`, `ns`, `nr`, `ppp_protocol`, `auth_protocol`, `username`, `password`, `chap_response`, `payload`, `truncated`

An SCCRQ opens a tunnel; the control connection, its sessions and the PPP negotiation they carry are collected into one event, produced when the client sends StopCCN (`endReason` `client_close`), after `conn_timeout` of silence (`timeout`), at 48 frames (`max_frames`), when the 256-tunnel table evicts it (`evicted`) or on shutdown. Datagrams that belong to no tunnel are produced on their own without a reply.

Control frames: `command` copies `message_name` (`SCCRQ`, `SCCCN`, `ICRQ`, `ICCN`, `HELLO`, `StopCCN`, `ZLB`, ...). Writes set `status` to the message the honeypot sent: `SCCRP`, `ICRP` (with `assigned_session_id`) or `ZLB`.

PPP frames (data messages): `ppp_protocol` is `LCP`, `PAP` or `CHAP` and `command`/`status` are `<ppp_protocol> <code name>`, e.g. `LCP Configure-Request`, `PAP Authenticate-Nak`, `CHAP Challenge`. `auth_protocol` (`PAP`, `CHAP-MD5`, `MS-CHAPv2`) is set on LCP frames carrying an Authentication-Protocol option and on credential frames. PAP Authenticate-Request sets `username` and `password`; CHAP Response sets `username` (the CHAP name) and `chap_response` (hex value). Every authentication attempt is rejected.
