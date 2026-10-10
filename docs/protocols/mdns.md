# `mdns` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of read frames: `direction`, `command`, `path`, `questions` (`qname`, `qtype`, `qtype_name`, `qclass`), `payload`, `truncated`

`command`/`path` are the first question's qtype name and qname. The handler does not reply.
