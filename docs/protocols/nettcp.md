# `nettcp` decoded data

Transport: TCP (default rule: tcp/4025 and tcp/4026, Visual Studio remote debugger `msvsmon`; the handler does not depend on the port, the Via is read from the preamble). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-record frames: `direction`, `command`, `path`, `status`, `version`, `mode`, `content_type`, `fault`, `payload`, `truncated`

Each frame is one .NET Message Framing ([MS-NMF]) record, the framing used by WCF `NetTcpBinding`. `payload` is the raw record. `command` is the record name (`Version`, `Mode`, `Via`, `KnownEncoding`, `ExtensibleEncoding`, `UpgradeRequest`, `PreambleEnd`, `SizedEnvelope`, `UnsizedEnvelope`, `End`, `Fault`, `PreambleAck`), or `0x..` for an undefined record type. `path` is the Via URI. `version` is `major.minor`. `mode` is `singleton-unsized`, `duplex`, `simplex` or `singleton-sized`. `content_type` is the known encoding's content type, the extensible encoding string, or the upgrade protocol of an `UpgradeRequest`. `fault` is the full fault string, and `status` on a write frame is its short name (`UnsupportedVersion`, `UnsupportedMode`, `ContentTypeInvalid`, `UpgradeInvalid`). `truncated` marks a record cut by the 64 KiB cap or by the client disconnecting mid-record.

Replies: `PreambleEnd` gets `PreambleAck`, and `End` gets `End` (then close). An unsupported version, mode or encoding, and any `UpgradeRequest` (no SSPI or TLS upgrade is emulated), get a `Fault` record and the session closes. Envelopes are recorded without a reply.

[MS-NMF]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nmf/
