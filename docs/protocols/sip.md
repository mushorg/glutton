# `sip` decoded data

Transport: UDP, TCP and TLS (implicit TLS on TCP/5061; see
[TCP and TLS](#tcp-and-tls)). Shared encodings and frame fields are described in
[Logging and producers](../logging.md#decoded-data).

`decoded` is an array of per-direction frames. On UDP one event covers a call
dialog (see [UDP dialogs](#udp-dialogs)); on TCP and TLS one event covers a
connection.

## Fields

| Field | Set on | Meaning |
| --- | --- | --- |
| `direction` | all | `read` (from attacker) or `write` (from honeypot). |
| `command` | all | SIP method on reads (and on the honeypot's own `BYE`); `rtp` on media summary frames. |
| `path` | reads | Request-URI. Toll-fraud scanners' dialed numbers show up here. |
| `status` | writes | Response code (`100`, `180`, `200`, `401`, …). |
| `from` / `to` | messages | `From` / `To` headers. |
| `call_id` | messages, media | `Call-ID`; also on media summary frames. |
| `user_agent` | messages | Client `User-Agent` on reads (every header, joined with `, `, when a client sends more than one), the honeypot `Server` header on writes. |
| `username` | reads | Digest `Authorization` username. |
| `realm` / `nonce` / `digest_uri` / `digest_response` / `algorithm` / `qop` / `nc` / `cnonce` | reads | Digest `Authorization` (or `Proxy-Authorization`) fields (see [Digest credentials](#digest-credentials)). |
| `tool` | reads | Fingerprinted scanner/dialer behind the request (see [Tool fingerprint](#tool-fingerprint)). |
| `called_number` | non-REGISTER requests | Normalized dialed number (see below); for REFER the transfer target. |
| `variant` / `visit` | writes | Response variant and the source IP's visit number (see [Returning sources](#returning-sources)). |
| `payload` | messages | Raw bytes as received or sent. |
| `truncated` | all | UDP: the datagram exceeded 4096 bytes. TCP: the message body exceeded 4096 bytes. Media: see [Call media](#call-media-udp). |
| `dropped` | UDP writes | The `udp_reply_limit` budget kept this reply from leaving; the client never received it. |
| `ssrc` | media | RTP SSRC (hex). |
| `codec` | media | Answered encoding name (e.g. `PCMU`), or `pt<N>`. |
| `packets` / `lost` | media | Packets received / gaps in the sequence numbers. |
| `duration_ms` | media | Recorded audio length. |
| `dtmf` | media | RFC 4733 telephone-event digits `0-9*#A-D` in order, one per event. |
| `payload_hash` | media | Hash of the stored WAV file. |

**`called_number`** is the Request-URI user (else the `To` user; for a REFER
the `Refer-To` user) with URI
parameters and the separators `-.() ` removed and a leading `+` kept. It is set
only when the rest is digits, `*` and `#`. For example,
`sip:+44 (20) 7946-0000@host` gives `+442079460000`, and `sip:asterisk@host`
gives none.

## Digest credentials

The challenge has the shape chan_pjsip sends (`res_pjsip_authenticator_digest`
and pjsip's `pjsip_auth_srv_challenge`): a nonce of the unix time, a slash and
32 hex digits, a 16-hex-digit `opaque`, and lowercase `algorithm=md5`:
`WWW-Authenticate: Digest realm="asterisk",nonce="1761350400/aab6286c0303e819fe6038a1b16143f3",opaque="0123456789abcdef",algorithm=md5,qop="auth"`.
Events from older sensors show a 16-hex-digit nonce, no `opaque` and
`algorithm=MD5`.

When the `auth` variant challenges a REGISTER or INVITE, the client re-sends it
with a digest `Authorization` (or `Proxy-Authorization`) header computed from a
nonce the honeypot issued. Because the nonce is ours, the recorded `response`
together with `username`, `realm`, `nonce`, `digest_uri`, `qop`, `nc` and
`cnonce` is enough to recover the password the scanner is guessing by running a
wordlist against it offline (e.g. hashcat `-m 11400`). The password itself is
never sent on the wire; `digest_response` is the attacker's keyed hash of their
guess, not a credential of ours. Only digest credentials are parsed; other
schemes (Basic, …) are left in `payload` only.

## Tool fingerprint

`tool` names the scanning or war-dialing tool behind a request, matched first on
the `User-Agent` (SIPVicious — both the classic `friendly-scanner` and the
rewrite — `sipcli`, `sipsak`, `pplsip`, `zxcvfdf` (the `zxcvfdf11` dial-prefix
tester), `VaxSIPUserAgent`, `sundayddr`, `SipSlaughter`, `Architect-TCP` and
others, plus `voip` for a `User-Agent` of exactly `VOIP`) in any of the
request's `User-Agent` headers. Failing that, it matches on a header habit that
survives a changed `User-Agent`: SIPVicious defaults its `From`/`To` domain to
`1.1.1.1`, builds its Via branch as `z9hG4bK-<decimal>` (with `rport`) and its
`From` tag as the hex of `<data>\x01<decimal>` (svhelper `createTag`), and
SipSlaughter reuses one `mrb-<hex>-<hex>` token in its `Call-ID`
(`…@pbx`), Via branch and `From` tag. Fleets that forge their `User-Agent` are
named by their tell instead:

| `tool` | Tell |
| --- | --- |
| `sqli-from` | SQL injection (`')or('x'='x`) in the `From`, `Contact` or `P-Preferred-Identity` user. |
| `zoiper-fleet` | SDP `s=Zoiper` behind a `User-Agent` that does not say Zoiper (a phone model that changes every call). |
| `sippts` | No `User-Agent`, a numeric `N-N-N` `Call-ID` and a digits-only Via branch (`z9hG4bK<digits>`), sippts' habits with its default `pplsip` agent removed. |
| `pjsip-python` | No `User-Agent` and pjsip's `z9hG4bKPj` Via branch: a script on the pjsip Python bindings (real pjsip phones and Asterisk send a `User-Agent`). |
| `sip-scan-call` | SDP session name `s=SIP Scan Call` (media at `0.0.0.0`): a dial fleet that rotates its `User-Agent` (2N IP Audio Kit, Gequdio, OpenSIPS). |
| `options-ping` | `OPTIONS` with no `User-Agent`, `Call-ID: 1` and a one-character Via branch (the `OPTIONS sip:1@1` liveness probe sent from many networks). |

`User-Agent` matches win over these. It is a triage hint, not proof: a scanner
can forge any header.

## Responses

This is the default (`answer` variant) behavior. Other variants change it; see
[Returning sources](#returning-sources).

| Request | Reply |
| --- | --- |
| OPTIONS, REGISTER (with or without credentials), BYE | `200` (OPTIONS with `Accept-Encoding: identity` and `Accept-Language: en`, as chan_pjsip) |
| INVITE | `100`, `180`, then after a 2–6 s ringing delay `200` with an SDP answer (see below) |
| SUBSCRIBE, MESSAGE, NOTIFY, PUBLISH, REFER, UPDATE, INFO | `401` challenge, then `403` after credentials |
| REFER inside an answered UDP call | `202`, then `NOTIFY` (`message/sipfrag` `SIP/2.0 100 Trying`) and, after a ringing delay, `NOTIFY` `SIP/2.0 200 OK` (see [UDP dialogs](#udp-dialogs)) |
| re-INVITE inside an answered UDP call | `200` with the same SDP answer |
| REGISTER or OPTIONS for an extension outside `sip.extensions` (when set) | `404 Not Found` |
| CANCEL, PRACK | `481` |
| CANCEL while the INVITE is still ringing | `200`, and the INVITE gets `487 Request Terminated` |
| anything else | `501` |

Answering INVITE makes toll-fraud scanners go on to dial, so their numbers show
up in `path`.

**SDP answer.** The answer has one `m=` line per offered one, in order (RFC 3264
section 6). The first `RTP/AVP` audio stream offering PCMU (else PCMA) is
accepted on an even port in 10000–19998, with the offer's `telephone-event`
if any. Every other stream (video, SRTP `RTP/SAVP`, a second audio stream, an
audio stream with neither codec) is rejected with port `0`. An offer without
any `m=` line, as SipSlaughter sends, is answered without one, and an INVITE
without SDP gets a PCMU offer. The status stays `200` either way, where a real
Asterisk would send `488`, so toll-fraud tools keep dialing; a call with no
accepted audio stream records no media. Events from older sensors answer every
offer with `m=audio … RTP/AVP 0`.

**Rejected first INVITEs.** The first `sip.reject_invites` (default 2) new INVITE
calls in a source IP's first visit get `100` then `404 Not Found` instead, so the
scanner tries its next dial prefix. Later visits are never rejected, so a scanner
that sends one INVITE per visit still reaches the early-media, challenged or busy
outcomes. The count starts over only once the source is forgotten (`recall.ttl`
or eviction).

**Challenged REGISTER.** With `sip.register_challenge: true` (default off) an
unauthenticated REGISTER gets a `401` digest challenge in every variant, and any
credentials in the retry are accepted with `200`. A REGISTER-only scanner then
reveals the `username` and digest it guesses with (`nonce`, `digest_response`, …)
and still reaches the INVITE stage. On UDP the `401` opens a dialog like an
INVITE does, so the retry (same `call_id`, higher CSeq) lands in the same event
(`read` REGISTER, `write` 401, `read` REGISTER with `username`, `write` 200,
`endReason` `handler_close`); a scanner that never retries is produced when the
dialog idles out (`timeout`).

**Extension leak.** With `sip.extensions` set (default empty), REGISTER (by its
`To` user) and OPTIONS (by its Request-URI user) for an extension outside the
list get `404 Not Found`; listed extensions get the answers above. Asterisk's
chan_pjsip answers every extension alike, so enumerators such as svwar, which
compare a known-bad extension's reply with the others, stop there; this makes
the PBX look like chan_sip with `alwaysauthreject=no`, so they find the listed
extensions and go on to crack them. INVITE dial strings are not affected.

**Contact and Via port.** The `Contact` of the `180`, `183` and `200`, and the
`Via` of the honeypot's own BYE, name the port the INVITE arrived on (falling
back to the Request-URI port, then 5060, only when that is unknown). A call to a
high port is therefore not told to ACK on 5060.

**NAT.** The top `Via` of each response gets `received=<source IP>` when the
client asked for `rport` or its sent-by host differs from the packet source. A
valueless `rport` is filled with the source port (RFC 3261 §18.2.1, RFC 3581).

## UDP dialogs

An INVITE opens a dialog keyed by source IP and `call_id`. Later datagrams with
that key (ACK, BYE, CANCEL, retransmits, re-INVITEs) append their frames to it,
so a call is one event.

- A retransmitted INVITE gets the latest response again: the `180` while
  ringing, then the final response.
- The final response (`200`, `404` or `487`) is resent at RFC 3261 T1 backoff
  (0.5 s doubling to 4 s) until an ACK arrives. Each resend is a `write` frame.
  A source that already left three final responses unACKed in the visit (see
  Escalation below) gets each later final response once: no resends, but the
  64*T1 wait, the BYE after a `200` and the `endReason` are unchanged. The
  dial-prefix testers seen so far (`zxcvfdf11`, `pplsip`) never ACK, so this
  drops about a dozen datagrams per call to a peer that does not read them.
- The ACK to a `404` or `487` produces the dialog with `client_close`. After
  64*T1, an unACKed `404` ends with `timeout` and an unACKed `487` with
  `client_close`, without a BYE.
- A re-INVITE (To tag ours) after the `200` gets `200` with the same SDP
  answer, resent until ACKed, instead of ringing as a new call.
- A REFER after the `200` (a transfer, as sippts `sipinvite` and toll-fraud
  callers try) gets `202 Accepted` and a `NOTIFY` (`Event: refer`,
  `message/sipfrag` `SIP/2.0 100 Trying`); after a 2–6 s delay a second
  `NOTIFY` reports `SIP/2.0 200 OK` and ends the subscription. The NOTIFYs are
  `write` frames with `command` `NOTIFY`, sent to the caller's source address;
  the caller's `200` to them joins the event as a `read` frame with `status`.
  Nothing is dialed: the target is only recorded in the REFER frame's
  `called_number`. A REFER without `Refer-To` gets `400`; a REFER before the
  call is answered gets the `401` above.
- If no ACK to the `200` arrives within 64*T1 (32 s), the honeypot hangs up like
  Asterisk/pjsip. It sends a `write` frame whose `command` is `BYE`
  (`Reason: SIP ;cause=408 ;text="Request Timeout"`, sent to the caller's source
  address) and produces the dialog with `timeout`.

Datagrams outside a dialog (OPTIONS, REGISTER, a stray ACK/BYE) are still one
event each, with `handler_close`.

**`endReason` values:**

| `endReason` | When |
| --- | --- |
| `client_close` | A BYE or CANCEL was answered, or a `404`/`487` was ACKed (or a `487` timed out). |
| `timeout` | No datagram for `conn_timeout` (at least 32 s), an unACKed `200` or `404`. |
| `max_frames` | The dialog reached 32 frames. |
| `evicted` | 256 dialogs are open. |
| `handler_close` | Shutdown, and single datagrams outside a dialog. |
| `read_error` | The message did not parse. |

## Parsing

Header lines ending in a bare LF are accepted (replies are always CRLF). A UDP
datagram that was not truncated may omit the empty line after the headers.
`payload` keeps the raw bytes either way. A message that still does not parse is
one `read` frame with no `command` and `endReason` `read_error`.

Generic UDP peeks the SIP start line (CRLF or LF) and reroutes it here from any
port.

## Returning sources

Write frames carry `variant` (the response variant) and `visit` (the source IP's
visit number, 1 for a first visit). A visit is all SIP traffic (TCP and UDP) from
one source IP with no gap longer than `recall.visit_gap` (default 30 min). Each
new visit moves to the next variant, so the same scanner sees a different
outcome when it comes back. A dialog keeps the variant of the visit it started
in.

| Variant | Visits | Behavior |
| --- | --- | --- |
| `answer` | 1, 5, … | As described in [Responses](#responses), including the `sip.reject_invites` `404`s. |
| `progress` | 2, 6, … | INVITE gets `100`, then `183 Session Progress` carrying the SDP answer (early media; same To tag and `Contact` as the `200`) instead of `180`, then the `200`. On UDP the caller's RTP to that SDP port is recorded from the `183` on. |
| `auth` | 3, 7, … | REGISTER and INVITE without credentials get `401` (`WWW-Authenticate` digest, no `100` first). With an `Authorization` header they are handled like `answer`. On UDP the ACK to the `401` keeps the dialog open, so the authenticated re-INVITE (same `call_id`, higher CSeq) lands in the same event. |
| `busy` | 4, 8, … | REGISTER is accepted. INVITE rings (`100`, `180`), then gets `486 Busy Here` instead of the `200`. On UDP its ACK produces the dialog with `client_close`. |

Later visits go straight to their variant; the `sip.reject_invites` `404`s apply
only in the first visit.

**Escalation within a visit.** Every INVITE final response (`200`, `401`, `486`)
that the caller never ACKs (64*T1) moves the source one variant further for the
rest of the visit, skipping `answer`:
`answer` → `progress` → `auth` → `busy` → `progress` …. A dial tester that only
reads the status code then sees a different outcome on its next call, instead of
the same ignored `200` until `recall.visit_gap` passes. The rejected `404`s and
the `487` after a CANCEL do not count, and the count starts over with each visit.

## Call media (UDP)

Enabled by `sip.record_media` (default on).

**Binding.** When a dialog sends a `200 OK`, the port in its SDP answer (an even
port in 10000–19998) is bound to the call for the caller's signaling IP and the
`c=` address of its offer. The answer's `c=` is the Request-URI IPv4 host, or the
address the INVITE arrived at when the Request-URI names a host. RTP from those
addresses to that port joins the dialog instead of producing `udp` events. Each
packet re-arms the dialog's idle timeout (up to 12000 packets), so a call stays
open while the caller talks. Nothing is sent back.

**Summary frames.** When the dialog is produced, each RTP stream (SSRC, up to 4)
adds one `read` frame at the end with `command` `rtp`, `call_id`, `ssrc`,
`codec`, `packets`, `lost`, `duration_ms`, `dtmf`, `payload_hash` and
`truncated` (see [Fields](#fields)).

**Audio.** PCMU/PCMA audio is placed by RTP timestamp (lost packets and silence
suppression become silence) and stored as an 8 kHz mono µ-law/A-law WAV file
under `payloads/rtp/<payload_hash>`. Other codecs (the honeypot never answers
with them) are counted but not recorded.

**`truncated`** is set when one of these caps dropped data:

- the call's 120 s audio cap;
- the 64 MiB cap across open calls;
- the 64-digit DTMF cap;
- more than 4 SSRCs were sent (on the last stream's frame).

RTP that arrives after the dialog was produced, from other addresses, or to other
ports goes to the `udp` catch-all as before.

## TCP and TLS

TCP/5060 and TLS/5061 (`tls: true`, so the handler sees plaintext and the event
carries `tls`) produce one event per connection, with `endReason` from the
connection (`client_close`, `timeout`, `read_error` and so on), unless a call
continues on a later connection (see below).

**Calls across connections.** RFC 3261 section 18 lets a client open a new
connection for a later request of the same call, and some dialers do: the
"SIP Scan Call" fleet closes the connection after the `200` and sends the ACK
over a new one about 10 s later. When a connection ends (`client_close`,
`client_reset`, `read_error` or `timeout`) with a call still open (a final
response not yet ACKed, or an answered call without BYE), its event is held
for `conn_timeout` (default 45 s). A new connection from the same source IP
whose request carries that `call_id` takes it over: the held frames come first
in the new connection's event, which keeps the first connection's
`startedAt`/`srcPort` and ends with the last one's `endReason`. A held
connection nobody takes over is produced when the hold passes, with its own
`endReason`. This also delays by up to `conn_timeout` the events of TCP callers
that never ACK (most toll-fraud tools). Up to 256 connections are held; beyond
that they are produced at once.

The generic `tcp` catch-all also peeks the start line and reroutes SIP from any
other TCP port (for example 65060) here, as it does for UDP. SIP wins over HTTP
for `OPTIONS sip:... SIP/2.0`; the `SIP/2.0` version token decides.

**Framing.** Messages are framed by `Content-Length` (RFC 3261 §18.3; compact
`l:` accepted, a missing header means no body). A message split across segments
is one `read` frame, and several pipelined messages are answered in order.

- A `Content-Length` that is not a number or exceeds 65536, or headers longer
  than 8 KiB without an empty line, end the connection with `read_error` after a
  `read` frame of what arrived.
- A framed message that does not parse is a `read` frame without `command`, and
  the connection continues.
- CRLF keepalive pings (`\r\n\r\n`, RFC 5626 §4.4.1) get a `\r\n` pong and
  produce no frames.

**Calls** behave as on UDP: the variant, the 2–6 s ringing delay, the
first-visit `sip.reject_invites` `404`s, CANCEL → `200` + `487`, the latest
response replayed to a retransmitted INVITE (same CSeq), and an `auth`
re-INVITE answered on the same connection. The differences:

- A reliable transport does not resend final responses.
- If the ACK does not arrive within 64*T1 (32 s), the unACKed final counts
  towards the variant escalation (the next call on the same connection already
  gets the next variant). An unACKed `200` is hung up with a `BYE` `write` frame
  whose `Via` names `TCP` or `TLS`; the connection stays open.
- Up to 16 calls per connection are tracked; later INVITEs get `100`, `180` and
  `200` at once.
- REFER and re-INVITE inside an answered call are not handled as on UDP: REFER
  gets the `401`/`403` of the [Responses](#responses) table, and a re-INVITE
  rings as a new call.
- Write frames have no `dropped`: the TCP reply budget (`tcp_reply_limit`)
  fails the write and ends the connection instead.

**Limits.** A connection ends with `max_frames` at 64 frames. Caller RTP of a TCP
or TLS call is not recorded; it goes to the `udp` catch-all.
