# `opcua` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `message_type`, `service`, `endpoint_url`, `security_policy`, `application_uri`, `application_name`, `username`, `password`, `payload`

`command` is `service` (or `message_type` if empty). `path` copies `endpoint_url`. ActivateSession UserName identity tokens set `username` and `password`: plaintext when the token is unencrypted, hex of the ciphertext when the token names an `EncryptionAlgorithm` (or the bytes are not UTF-8).

`service` names the UA service: `Hello`, `OpenSecureChannel`, `GetEndpoints`, `FindServers`, `CreateSession`, `ActivateSession`, `CloseSession`, `Browse`, `BrowseNext`, `Read`, `Write`, `Call`, `TranslateBrowsePaths`, `CreateSubscription`, `CloseSecureChannel`; `UNKNOWN` only for undecodable frames. `Browse` of the Objects folder (`i=85`) is answered with two fake nodes (`Server`, `PLC`); other nodes get `BadNodeIdUnknown`. Other services not listed as implemented in the handler get a ServiceFault `BadServiceUnsupported`. The server nonce is random per session.
