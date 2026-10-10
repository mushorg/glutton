# `rdp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

Routing: `tcp dst port 3389`, plus any port through the `tcp` catch-all when the first bytes are a TPKT-framed X.224 Connection Request (whatever the cookie length, with or without Spicy).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `cookie`, `protocols`, `ntlm_domain`, `ntlm_user`, `ntlm_workstation`, `ntlm_version`, `channel_id`, `client_data`, `client_info`, `header`, `payload`, `truncated`

`command` is `ConnectionRequest`, `ConnectionConfirm`, `TLSClientHello`, `TLSHandshake`, `MCSConnectInitial`, `MCSConnectResponse`, `NTLMNegotiate` (client Type 1), `NTLMChallenge` (server Type 2 reply), `NTLMAuthenticate` (client Type 3), `TSRequest` (CredSSP frame with no recognised NTLM type), or one of the MCS domain PDUs below. CredSSP/NLA (HYBRID) follows TLS: the server replies to Negotiate with a random Challenge; the Authenticate frame carries `ntlm_domain`, `ntlm_user`, and `ntlm_workstation` decoded from the UTF-16LE payload. The Confirm selects a single protocol (CredSSP, else TLS, else standard). `TLSClientHello` holds all client handshake bytes (capped, `truncated` set if cut) and `TLSHandshake` the server's flight; SNI/ALPN are in the event's `tls` field. `cookie` is `mstshash`; `protocols` is the RDP_NEG bitmask name. `header` is the TPKT struct and is present only on X.224/TPKT frames; it is `null`/absent on TLS and CredSSP frames. The TLS certificate CN and the NTLM Challenge identity (computer name, workgroup) are taken from the stable sensor identity configured via `rdp.computer_name` / `rdp.domain_name`; they match so scanners harvesting the NTLM Challenge see a consistent host. The NTLM Challenge TargetInfo includes MsvAvNbDomainName, MsvAvNbComputerName, MsvAvDnsDomainName, MsvAvDnsComputerName, and MsvAvTimestamp; a VERSION block is added when the client's Negotiate sets NEGOTIATE_VERSION.

`ntlm_version` on `NTLMAuthenticate` is `NTLMv2`, `NTLMv1` or `anonymous`, from the NtChallengeResponse length. The response itself (and so a crackable hash) is not a decoded field; it stays in the raw `payload` with the server challenge in the `NTLMChallenge` write.

### Connection sequence after MCS (TLS or standard RDP security without CredSSP)

`MCSConnectInitial` reads carry `client_data`, parsed from the GCC `Duca` client data blocks: `client_name`, `client_build`, `desktop_width`, `desktop_height`, `keyboard_layout` (LCID, e.g. 1033 = 0x409 en-US), `high_color_depth`, `encryption_methods` (CS_SECURITY bitmask), and `channels` (static virtual channel names such as `rdpdr`, `cliprdr`, `rdpsnd`). The `MCSConnectResponse` assigns each requested channel an ID from 1004 (I/O channel 1003) and announces ENCRYPTION_LEVEL_NONE.

The handler then follows the MCS domain sequence. Several TPKT PDUs in one read are split, and a PDU split across reads is reassembled (a partial PDU left at disconnect is stored with `truncated`):

| Read `command` | Write reply |
| --- | --- |
| `ErectDomainRequest` | none |
| `AttachUserRequest` | `AttachUserConfirm` (user channel 1007) |
| `ChannelJoinRequest` (`channel_id`) | `ChannelJoinConfirm` (`channel_id`) |
| `ClientInfo` (`channel_id` 1003, `client_info`) | `LicenseErrorAlert` (`status` `STATUS_VALID_CLIENT`), `SetErrorInfo` (`status` `ERRINFO_SERVER_DENIED_CONNECTION`), `DisconnectProviderUltimatum`; then the connection closes |
| `SecurityExchange` / `SendDataRequest` | none |
| `X224Data` (unknown MCS PDU) | none |

`client_info` is the Client Info PDU (TS_INFO_PACKET): `domain`, `username`, `password_len` (characters), `alternate_shell`, `working_dir`, `client_address`, `client_dir`, `autologon`, and `encrypted` when the client used standard RDP security encryption (then nothing else is decoded). The password is never a decoded field; it is only in the raw `payload` (UTF-16LE). Sessions are capped at 128 frames (`endReason` `max_frames`).

Not emulated: standard RDP security key exchange (RSA/RC4), licensing beyond the valid-client shortcut, the capability exchange (Demand/Confirm Active), input events, and a desktop. No login succeeds.
