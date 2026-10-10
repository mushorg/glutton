# `rtsp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `cseq`, `user_agent`, `auth_scheme`, `username`, `digest_response`, `payload`, `truncated`

RTSP/1.0 (IP cameras, NVRs) on tcp/554, 8554 and 10554, and on any port the catch-all sees an RTSP request line (`<METHOD> <uri> RTSP/1.0`, or an RTSP-only method with an `rtsp://` URI). Read frames set `command` (method), `path` (request URI path; `/` for a bare `rtsp://host:port`), `cseq` and `user_agent`. Credentials set `auth_scheme` `basic` or `digest` (from `Authorization`) or `uri` (`rtsp://user:pass@host/...`), plus `username`. Digest also sets `digest_response`. Passwords are never copied into `decoded`; they stay in the raw `payload`. Writes set `status` (RTSP code) and `cseq`.

The honeypot answers as a Dahua-style camera (`Server: Rtsp Server/3.0`, realm `Login to <serial>`, the serial random per sensor process). `OPTIONS` gets `200` with `Public`. `DESCRIBE`/`SETUP`/`ANNOUNCE`/`RECORD` get `401` with Digest (per-session nonce) and Basic challenges, whatever credentials are sent. `PLAY`/`PAUSE`/`TEARDOWN`/`GET_PARAMETER`/`SET_PARAMETER` get `454`, unknown methods `501`, a missing or non-numeric `CSeq` `400`, and other versions `505`. No media is ever streamed. Up to 100 requests are recorded per connection (`endReason` `max_frames`). Bodies over 64 KiB are stored up to the cap with `truncated`. Non-RTSP traffic on the RTSP ports goes through the catch-all dispatch (HTTP, `tcp`).
