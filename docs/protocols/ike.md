# `ike` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `status`, `version`, `spi_i`, `spi_r` (hex), `encryption`, `prf`, `integrity`, `dh_groups`, `ke_group`, `notifies`, `vendor_ids` (hex), `nat_t`, `payload`, `truncated`

udp/500 and udp/4500 (`nat_t` when the non-ESP marker is present; replies keep it). `command` is the exchange name. Reads list every offered transform name (key length suffixed, e.g. `AES_CBC_256`); IKEv1 records header and Vendor IDs only, without a reply. IKEv2 IKE_SA_INIT requests get a stateless reply: `INVALID_KE_PAYLOAD` asking for MODP_2048/ECP_256/ECP_384 when the KE group differs, a full IKE_SA_INIT (chosen transforms, random KE and nonce) when it matches, or `NO_PROPOSAL_CHOSEN`. Writes set `status` and list the chosen transforms. Datagrams over 4096 bytes are capped with `truncated`.
