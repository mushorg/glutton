# `spice` decoded data

Transport: TCP (tcp/5900-5910 through the `rfb` rule, and any port where the catch-all sees the `REDQ` link magic). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `payload`, plus the fields below when the frame carries them.

| Field | Frame | Meaning |
| --- | --- | --- |
| `command` | read | `LinkMess` (SpiceLinkHeader + SpiceLinkMess), `AuthMechanism`, `Ticket`. Empty for a first read that does not start with `REDQ` |
| `command` | write | `LinkReply` (SpiceLinkHeader + SpiceLinkReply), `LinkResult` (4-byte result after the ticket) |
| `version` | read `LinkMess` | Client protocol version `major.minor` (`2.2` for every current client) |
| `connection_id` | read `LinkMess` | Session ID; omitted (0) for a new session, set when a client links a secondary channel |
| `channel_type` | read `LinkMess` | `main`, `display`, `inputs`, `cursor`, `playback`, `record`, `tunnel`, `smartcard`, `usbredir`, `port`, `webdav`, or the number |
| `channel_id` | read `LinkMess` | Channel instance, omitted when 0 |
| `common_caps`, `channel_caps` | read `LinkMess`, write `LinkReply` | Capability words as comma-separated 8-digit hex. Common bits: 0 auth selection, 1 SPICE auth, 2 SASL, 3 mini header (spice-gtk sends `0000000b`) |
| `auth_mechanism` | read `AuthMechanism` | `SPICE`, `SASL`, or the number |
| `password` | read `Ticket` | The password the client tried, decrypted from the RSA-OAEP ticket, in plaintext. Omitted for an empty password or a ticket that does not decrypt |
| `status` | write | Link error name: `OK`, `PermissionDenied`, `InvalidMagic`, `InvalidData`, `VersionMismatch` |

`payload` holds the raw bytes of each message, including the 16-byte link header. The `Ticket` payload is the 128-byte ciphertext as sent. A read frame cut short by a disconnect keeps the bytes that arrived (`endReason` `client_close`).

## Emulation

The server answers like spice-server (QEMU/KVM) with ticketing on. A `LinkMess` with major version 2 gets an accepting `LinkReply`: the server's RSA-1024 public key (DER SubjectPublicKeyInfo, 162 bytes), common caps `0000000b` (auth selection, SPICE auth, mini header; no SASL) and, for the main channel, channel caps `0000000f`. The key pair is generated once per process; spice-server makes one per link.

A client that set the auth selection cap then sends `AuthMechanism`; anything but `SPICE` gets a link error `InvalidData`. The client then sends the 128-byte ticket, which the honeypot decrypts with its private key (OAEP, SHA-1) and records as `password`. Every ticket gets `LinkResult` `PermissionDenied` (`07000000`) and the connection is closed, so no channel is ever established.

Link errors are sent as a full header and reply with a zeroed key, as spice-server does: `InvalidMagic` for a first read without `REDQ` (the first segment is kept in `payload`), `VersionMismatch` for a major version other than 2, and `InvalidData` for a link message under 18 or over 4096 bytes or with caps outside it.

## Routing

SPICE clients speak first. On the `rfb` ports (5900-5910) the dispatcher waits up to 300 ms for client bytes before the RFB banner: a client that opens with `REDQ` goes to `spice`, while silent (RFB) clients, clients that send anything else, and clients that disconnect get the [`rfb`](rfb.md) handshake. RFB banners are therefore sent 300 ms after the connection is accepted. On other ports the catch-all routes a first segment starting with `REDQ` here. The catch-all on 5900 itself sends the RFB banner first and does not peek, so SPICE on 5900 needs the `rfb` rule.

A minimal SPICE scanner sends a 34-byte `LinkMess` for the main channel with no caps at all (payload SHA-256 `b62092d9…bf205`). With no auth selection cap it would send the ticket right after the `LinkReply`. Older sensors routed it to `tcp` and answered `random` (Ochi event a1089002-b561-402e-8143-7cfe51e439ac, tcp/5907); the client waited about 100 s and reset the connection.
