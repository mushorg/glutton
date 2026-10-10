# `hiflying` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `payload`, `truncated`

Hi-Flying Wi-Fi serial module configuration (udp/48899; HF-A11, HF-LPB100, HF-LPT and USR-WIFI232 clones). `command` is `DISCOVER` (the factory assist password `HF-A11ASSISTHREAD`), `ENTER_AT` (`+ok`), `AT+<VERB>` (e.g. `AT+WSKEY`), or `UNKNOWN`. `path` is the argument of a set command (`AT+<VERB>=<args>`); Wi-Fi keys and passwords set by the client (`AT+WSKEY`/`AT+WAKEY` key field, `AT+ASWD`, the `AT+WEBU` password) are replaced with `***` in both `path` and `payload`. `DISCOVER` gets a `write` `DISCOVER_REPLY` (`<ip>,<MAC>,HF-LPB100`) from a stable per-sensor module identity on a private LAN address, at most once per source IP per minute. `+ok` puts the source into command mode without a reply. AT commands are answered only in command mode (discovery and `+ok` from the same source within 5 minutes): `status` `OK` with a canned value (`+ok=<value>\r\n\r\n`) or `ERR` (`+ERR=-2\r\n\r\n`), at most 32 replies per source per minute; `AT+Q` leaves command mode. Set, reboot and OTA (`AT+UPURL`) commands are acknowledged and never acted on. Datagrams over 1024 bytes are capped with `truncated`.
