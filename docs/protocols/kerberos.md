# `kerberos` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of read frames: `direction`, `command`, `path`, `msg_type`, `msg_name`, `pvno`, `realm`, `sname`, `cname`, `etypes`, `from`, `nonce`, `status`, `payload`, `truncated`

`command` copies `msg_name`; `path` copies `sname`. An AS-REQ with a realm gets a `write` frame (`command`/`msg_name` `KRB-ERROR`, `status` `KDC_ERR_PREAUTH_REQUIRED`) carrying METHOD-DATA (PA-ETYPE-INFO2 + PA-ENC-TIMESTAMP); TGS-REQ is parse-only; no AS-REP is ever sent. Truncated or non-DER datagrams still emit a frame with raw `payload` (`msg_name` `UNKNOWN`). Generic UDP peeks APPLICATION 10/12 and reroutes here.
