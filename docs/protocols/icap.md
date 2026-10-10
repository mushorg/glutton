# `icap` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `user_agent`, `encapsulated`, `preview`, `http_request`, `http_status`, `payload_hash`, `payload`, `truncated`

ICAP/1.0 (RFC 3507) on tcp/1344, and ICAPS on tcp/11344 (`tls: auto`). `command` is the ICAP method (`OPTIONS`, `REQMOD`, `RESPMOD`), `path` the service path of the `icap://` URI (`/` for the bare root). `encapsulated` and `preview` copy the request headers. `http_request` / `http_status` are the first lines of the encapsulated HTTP request and response headers. `payload` is the wire request: ICAP head, encapsulated HTTP headers and the chunked body.

The honeypot plays the stock c-icap echo service (`icap.service`, `icap.istag`). `OPTIONS` on any service gets `200 OK` advertising `RESPMOD, REQMOD`, `Preview: 1024` and `Allow: 204`. A previewed body that does not end in `0; ieof` gets `100 Continue`. The rest of the body is a separate read frame with the same `command`. `REQMOD`/`RESPMOD` then get `204 Unmodified` when the client sent `Allow: 204`, otherwise `200 OK` echoing the encapsulated HTTP headers and body. Other methods get `405`. Input that is not ICAP (an HTTP request line, a bad `Encapsulated` header, broken chunking) gets `400 Bad request` and the connection ends. Writes set `status` to the ICAP code.

The de-chunked body (preview and rest) is stored under `payloads/icap` and its SHA-256 recorded in `payload_hash` on the read frame that completed it. Bodies over 256 KiB are kept up to the cap with `truncated`; more than 1 MiB beyond the cap ends the session.
