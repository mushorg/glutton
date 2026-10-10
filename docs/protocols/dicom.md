# `dicom` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `path`, `status`, `pdu_type`, `called_ae`, `calling_ae`, `application_context`, `abstract_syntaxes`, `transfer_syntaxes`, `implementation_class_uid`, `implementation_version`, `username`, `message_id`, `sop_class_uid`, `sop_instance_uid`, `move_destination`, `payload_hash`, `payload`, `truncated`

DICOM Upper Layer (tcp/104, tcp/11112). `command` is the DIMSE command (`C-ECHO-RQ`, `C-FIND-RQ`, `C-STORE-RSP`, ...) for P-DATA-TF frames and the PDU name (`A-ASSOCIATE-RQ`, `A-RELEASE-RP`, `A-ABORT`) otherwise. `path` copies `called_ae`. Every association is accepted; C-ECHO/C-FIND/C-STORE/C-GET/C-MOVE writes set `status` `Success`, N-* services `UnrecognizedOperation`. A DIMSE message's command and data set PDUs are aggregated into one read frame (capped at 1 MiB with `truncated`); C-STORE data sets are stored under `payloads/dicom` and hashed into `payload_hash`. User identity usernames are recorded; passcodes are not copied into `decoded`.
