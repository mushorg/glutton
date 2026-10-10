# `rtps` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of read frames: `direction`, `command`, `version`, `vendor_id`, `vendor`, `guid_prefix`, `submessages` (`kind`, `flags`, `length`), `writer_entity_id`, `writer_sn`, `participant_guid`, `user_data`, `entity_name`, `domain_id`, `locators`, `vendor_strings`, `payload`, `truncated`

RTPS/DDS discovery (udp/7400, 7401, 7410, 7411). `command` is `DATA(p)` for an SPDP participant announcement (writer entity `000100c2`), `DATA(w)`/`DATA(r)` for SEDP, else the first non-INFO submessage kind; `UNKNOWN` if unparseable. Parse-only: no reply. `vendor` is set for known vendor IDs. `vendor_strings` are printable runs from vendor-specific parameters (heuristic). Truncated datagrams keep whatever parsed before the cut. Generic `udp` peeks the `RTPS` magic and reroutes here.
