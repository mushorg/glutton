# `dicom` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `pdu_type`, `called_ae`, `calling_ae`, `application_context`, `abstract_syntaxes`, `transfer_syntaxes`, `implementation_class_uid`, `implementation_version`, `username`, `message_id`, `sop_class_uid`, `sop_instance_uid`, `move_destination`, `query`, `payload_hash`, `payload`, `truncated`

The handler speaks the DICOM Upper Layer protocol used by PACS and imaging devices on tcp/104 and tcp/11112. One event is produced per TCP session.

## Frames

| Field | Set on | Meaning |
| --- | --- | --- |
| `command` | all | DIMSE command for P-DATA-TF frames (`C-FIND-RQ`, `C-STORE-RSP`, …); otherwise the PDU name (`A-ASSOCIATE-RQ`, `A-RELEASE-RP`, `A-ABORT`). |
| `pdu_type` | all | PDU name (`P-DATA-TF`, `A-ASSOCIATE-AC`, …). |
| `status` | writes | Association result (`Accepted`, `Rejected`) or DIMSE status (`Success`, `Pending`, …). |
| `called_ae`, `calling_ae`, `path` | A-ASSOCIATE-RQ | AE titles; `path` copies `called_ae`. |
| `abstract_syntaxes`, `transfer_syntaxes` | A-ASSOCIATE-RQ | Proposed SOP classes and transfer syntaxes. |
| `implementation_class_uid`, `implementation_version` | A-ASSOCIATE-RQ | Client implementation, e.g. `OFFIS_DCMTK_360` for DCMTK tools. |
| `username` | A-ASSOCIATE-RQ | User identity username. Passcodes are never copied into `decoded`. |
| `message_id`, `sop_class_uid`, `sop_instance_uid` | DIMSE frames | From the command set. On writes, `message_id` is the request being answered. |
| `move_destination` | C-MOVE-RQ | AE title the client asked the images to be sent to. |
| `query` | C-FIND/C-GET/C-MOVE-RQ | Search keys from the identifier (see below). |
| `payload_hash` | C-STORE-RQ | SHA-256 of the stored data set. |
| `payload`, `truncated` | all | Raw PDU bytes. A DIMSE request's command and data set PDUs are aggregated into one read frame, capped at 1 MiB with `truncated`. |

### `query`

`query` maps PS3.6 keywords to values, for example `{"QueryRetrieveLevel": "STUDY", "PatientName": "*"}`.

- Unknown tags are keyed as `(gggg,eeee)`.
- Binary values are hex encoded, and values are capped at 256 bytes.
- Sequences (e.g. `ScheduledProcedureStepSequence`) appear with an empty value.
- The identifier is decoded with the transfer syntax negotiated for its presentation context. Big endian and deflated identifiers are not decoded.

## Replies

Every association is accepted, as a stock DCMTK `storescp` (`OFFIS_DCMTK_364`). A malformed A-ASSOCIATE-RQ gets an A-ASSOCIATE-RJ.

| Request | Reply `status` |
| --- | --- |
| C-ECHO | `Success` |
| C-STORE | `Success`; the data set is stored under `payloads/dicom` (up to 8 MiB per data set) |
| C-FIND, Patient Root / Study Root / Patient-Study Only | One `Pending` per match, then `Success` |
| C-FIND, other models (e.g. modality worklist) | `Success` with no matches |
| C-FIND with an undecodable identifier | `IdentifierDoesNotMatchSOPClass` (0xA900) |
| C-MOVE | `MoveDestinationUnknown` (0xA801) |
| C-GET | `OutOfResources` (0xA702) |
| N-* services | `UnrecognizedOperation` |
| A-RELEASE-RQ | A-RELEASE-RP, then the connection closes |
| Unexpected or malformed PDU, or a PDU over 1 MiB | A-ABORT |

C-FIND matches come from a small fictional archive: three patients, each with one study, series and image. Matching supports `*`/`?` wildcards (case-insensitive), UID lists, and date/time ranges. Each `Pending` reply returns only the keys the client requested; keys the archive doesn't hold come back empty.

C-MOVE and C-GET are always refused, so the honeypot never connects to an attacker-supplied AE and never sends images.

A session ends after 4096 PDUs (`endReason` `max_frames`).
