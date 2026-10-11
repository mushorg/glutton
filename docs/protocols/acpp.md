# `acpp` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `version`, `flags`, `body_size`, `bad_checksum`, `key`, `status`, `error_code`, `payload`, `truncated`

Apple AirPort Admin protocol (ACP, tcp/5009), the protocol AirPort Utility uses to read and change base station settings. Every message starts with a fixed 128-byte big-endian header: magic `acpp`, version (`0x00030001`), an Adler-32 header checksum (computed with the checksum field zeroed), body checksum, body size (`-1` for a stream header with no body), flags, an unused word, command, error code, padding, and a 32-byte `key` that holds the password XORed with a static keystream. The layout follows airpyrt-tools (`acp/message.py`) and Metasploit's `Rex::Proto::ACPP`.

Each header is a `read` frame with `command` (`echo`, `flash_primary`, `flash_secondary`, `flash_bootloader`, `getprop`, `setprop`, `perform`, `monitor`, `rpc`, `auth`, `feat`, or `unknown`), `version` as hex, `flags`, `body_size`, and `key` as hex when it is not all zeros. `bad_checksum` is set when the header checksum does not match. When the header is valid and declares a body, up to 64 KiB of the body is read into the same frame's `payload` (`truncated` when the declared size was larger; the session then ends).

The honeypot answers each header with a body-less 128-byte reply header that carries the same command and an error code from Apple's CoreUtils error space. The `write` frame has `status` and `error_code`: `version` (-6715) for an unsupported version, `checksum` (-6713) for a bad header checksum, `unsupported` (-6735) for an unknown command, and `authentication` (-6754) for every known command, so no request is ever accepted. The specific codes are a best guess; the public references do not document them. Up to 8 headers are answered per connection (`endReason` `max_frames` after that). Data that does not start with `acpp` is recorded as a `read` frame without `command`, and the connection closes with no reply. A short header is recorded as received.
