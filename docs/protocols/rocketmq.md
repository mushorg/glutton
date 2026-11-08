# `rocketmq` decoded data

Transport: TCP (default rule: tcp/10911 and tcp/13911). Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `code`, `opaque`, `flag`, `language`, `version`, `remark`, `status`, `ext_fields`, `config`, `payload`, `truncated`

An Apache RocketMQ remoting frame is a big-endian uint32 total length (bytes after this field), a uint32 whose high byte is the serialize type (0 = JSON, 1 = ROCKETMQ binary) and whose low 24 bits are the header length, then the header and an optional body. Both header encodings are parsed; replies are always JSON.

- **`command`**: the RequestCode name (`GET_BROKER_RUNTIME_INFO`, `UPDATE_BROKER_CONFIG`, `GET_BROKER_CONFIG`, `HEART_BEAT`, …) or `CODE_<n>`. On write frames it repeats the request being answered.
- **`code`**: the request code on reads, the response code on writes.
- **`opaque`**: request ID; replies echo it.
- **`flag`**, **`language`**, **`version`**, **`remark`**, **`ext_fields`**: header fields as sent.
- **`status`** (write): `SUCCESS` or `REQUEST_CODE_NOT_SUPPORTED`.
- **`config`**: key/value pairs parsed from the properties body of `UPDATE_BROKER_CONFIG` / `UPDATE_NAMESRV_CONFIG` (the CVE-2023-33246 / CVE-2023-37582 exploit step).
- **`payload`**: the raw frame.
- **`truncated`**: set when the declared length exceeds 256 KiB or the client disconnected mid-frame. The session ends after it.

Replies (broker persona, version `V4_9_4`):

- `GET_BROKER_RUNTIME_INFO` (28) gets `SUCCESS` with a KVTable body (`brokerVersionDesc`, `brokerVersion`, `bootTimestamp`, `runtime`, zeroed counters).
- `GET_BROKER_CONFIG` (26) gets `SUCCESS` with a properties body.
- `UPDATE_BROKER_CONFIG` (25), `HEART_BEAT` (34) and `UNREGISTER_CLIENT` (35) get an empty `SUCCESS`. Nothing is applied or run.
- Oneway requests and response frames get no reply.
- Anything else gets `REQUEST_CODE_NOT_SUPPORTED` with remark ` request type <n> not supported`.

The MQVersion ordinal (`413` for `V4_9_4`) and the KVTable keys are from memory of the upstream source and were not checked against it.

Each TCP session produces one event and is capped at 32 requests.
