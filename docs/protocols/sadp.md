# `sadp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** One `read` frame per datagram (`direction`, `command`, `uuid`, `password`, `payload`, `truncated`), followed by one `write` frame (`direction`, `command`, `uuid`, `status`, `payload`) when the handler answers.

Hikvision SADP (Search Active Devices Protocol) discovery on udp/37020. Scanners (e.g. driftnet.io) and the SADP tool send `<?xml version="1.0" encoding="utf-8"?><Probe><Uuid>…</Uuid><Types>inquiry</Types></Probe>`. `command` is the lower-cased `<Types>` (`inquiry`, `activate`, …) or `unknown`. `uuid` is the request `<Uuid>`. `password` is the `<Password>` element of activate/modify probes, as sent (newer clients encrypt it). Fields are clipped to 128 bytes. Datagrams over 2048 bytes are capped with `truncated`.

Replies:

- `inquiry` → `<ProbeMatch>` (`status` `ProbeMatch`) echoing `Uuid` and `Types`. It describes an activated `DS-2CD2042WD-I` IP camera with a stable per-sensor serial, MAC (`c0-56-e3-…`), private `192.168.1.x` address, command port 8000, HTTP port 80, firmware `V5.4.5build 170124` and a `BootTime` a few days in the past.
- Other types (activate, update, reset, …) are recorded only.

The `ProbeMatch` element names were recalled from SADP replies of Hikvision cameras, not checked against a capture.
