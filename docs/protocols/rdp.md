# `rdp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

Routing: `tcp dst port 3389`, plus any port through the `tcp` catch-all when the first bytes are a TPKT-framed X.224 Connection Request (whatever the cookie length, with or without Spicy).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `cookie`, `protocols`, `ntlm_domain`, `ntlm_user`, `ntlm_workstation`, `ntlm_version`, `netntlmv2`, `nla_accepted`, `channel_id`, `client_data`, `client_info`, `header`, `payload`, `truncated`

`command` is `ConnectionRequest`, `ConnectionConfirm`, `TLSClientHello`, `TLSHandshake`, `MCSConnectInitial`, `MCSConnectResponse`, `NTLMNegotiate` (client Type 1), `NTLMChallenge` (server Type 2 reply), `NTLMAuthenticate` (client Type 3), `TSRequest` (CredSSP frame with no recognised NTLM type), or one of the MCS domain PDUs below. CredSSP/NLA (HYBRID) follows TLS: the server replies to Negotiate with a random Challenge; the Authenticate frame carries `ntlm_domain`, `ntlm_user`, and `ntlm_workstation` decoded from the UTF-16LE payload. The Confirm selects a single protocol (TLS if the client offered it, else CredSSP, else standard), so a typical TLS|CredSSP probe skips NLA and any password arrives in Client Info. `TLSClientHello` holds all client handshake bytes (capped, `truncated` set if cut) and `TLSHandshake` the server's flight; SNI/ALPN are in the event's `tls` field. `cookie` is `mstshash`; `protocols` is the RDP_NEG bitmask name. `header` is the TPKT struct and is present only on X.224/TPKT frames; it is `null`/absent on TLS and CredSSP frames. The TLS certificate CN and the NTLM Challenge identity (computer name, workgroup) are taken from the stable sensor identity configured via `rdp.computer_name` / `rdp.domain_name`; they match so scanners harvesting the NTLM Challenge see a consistent host. The NTLM Challenge TargetInfo includes MsvAvNbDomainName, MsvAvNbComputerName, MsvAvDnsDomainName, MsvAvDnsComputerName, and MsvAvTimestamp; a VERSION block is added when the client's Negotiate sets NEGOTIATE_VERSION.

CredSSP NTLM may be bare or SPNEGO-wrapped (Windows clients send a GSS NegTokenInit, then a NegTokenResp for Authenticate); both are unwrapped, the frame gets `spnego: true`, and the Challenge is wrapped in a NegTokenResp (accept-incomplete, NTLMSSP) when the Negotiate was. Older sensors only understood bare NTLM, so a SPNEGO client ended the session with a `TSRequest` read and no reply.

After an `NTLMAuthenticate` the honeypot fails the logon like Windows does, unless `rdp.credentials` or `rdp.guess_passwords` lists a password that verifies the Type 3 (any username): a write frame (`command` `TSRequest`, `status` `STATUS_LOGON_FAILURE`) carrying a CredSSP TSRequest with `errorCode` 0xC000006D. With neither list set (the default) that is the only NLA outcome. `guess_passwords` is capped at 64 entries and is tried after `rdp.credentials`. When a listed password matches, the write is `status` `NLA_ACCEPTED` (`nla_accepted` on that frame and the Authenticate), the follow-up `authInfo` (TSPasswordCreds) is opened into `ntlm_user`, `ntlm_domain`, and `nla_password` (the plaintext password), and the session continues into the MCS / Client Info path below. An unknown password cannot be accepted: the CredSSP confirmation is sealed with a key derived from that password. Client passwords are guessing attempts, not secrets, so they are recorded in plaintext. Clients that also offered TLS never reach this step. The `NTLMAuthenticate` frame also has `ntlm_server_challenge` (hex of the challenge we sent), `nt_response_len`, and, for NTLMv2, `netntlmv2` (a hashcat `-m 5600` string, `user::domain:challenge:proof:blob`), including when the logon fails. The generated computer name is persisted in `<var-dir>/rdp_computer_name`, so it is unique per sensor and stable across restarts (override with `rdp.computer_name`). The event's `scanner` is `rdp-nla-prober` for a known cookie-less NLA login fleet recognized by its payload hash.

`ntlm_version` on `NTLMAuthenticate` is `NTLMv2`, `NTLMv1` or `anonymous`, from the NtChallengeResponse length. NTLMv2 also sets `netntlmv2`. NTLMv1 and anonymous responses stay in the raw `payload` with the server challenge in the `NTLMChallenge` write.

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

`client_info` is the Client Info PDU (TS_INFO_PACKET): `domain`, `username`, `password` (plaintext guess), `alternate_shell`, `working_dir`, `client_address`, `client_dir`, `autologon`, and `encrypted` when the client used standard RDP security encryption (then nothing else is decoded, including the password). Sessions are capped at 128 frames (`endReason` `max_frames`).

Not emulated: standard RDP security key exchange (RSA/RC4), licensing beyond the valid-client shortcut, the capability exchange (Demand/Confirm Active), input events, and a desktop. NLA can complete only for a password in `rdp.credentials` or `rdp.guess_passwords` (the session key is password-derived, so an unknown password cannot be accepted). The later Client Info path still denies the session (`ERRINFO_SERVER_DENIED_CONNECTION`).
