# `cassandra` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `message`, `path`, `query`, `username`, `password`, `status`, `payload`

This is Apache Cassandra's legacy Thrift RPC on tcp/9160: framed transport (4-byte big-endian length) carrying binary-protocol messages. The handler accepts both strict (`80 01 00 <type>`) and old (name first) headers. `command` is the Thrift method name. On reads, `message` is `{name, type, seqid, strict, args}`. `type` is 1 call, 2 reply, 3 exception or 4 oneway. `args` maps field ids to decoded values: strings, numbers and lists, with structs and maps as objects. `args` is omitted when the argument struct does not decode within the caps (depth 8, 256 values). The handler also copies some arguments to top-level fields:

- `path`: the keyspace from `set_keyspace`
- `query`: the CQL text from `execute_cql_query`, `execute_cql3_query`, `prepare_cql_query` and `prepare_cql3_query`
- `username`/`password`: the plaintext values from `login` credentials

The classic probe is a bare `describe_cluster_name` CALL (criminalip, seqid 2).

Replies (`status` on writes, `command` echoes the method, `seqid` is echoed in the payload):

- `reply`: `describe_cluster_name` returns `Test Cluster`, `describe_version` returns `20.1.0`, `describe_partitioner` returns `org.apache.cassandra.dht.Murmur3Partitioner` and `describe_snitch` returns `org.apache.cassandra.locator.SimpleSnitch`. These are stock Cassandra 3.11 defaults. `login` and `set_keyspace` always succeed with an empty result.
- `exception`: any other CALL gets a TApplicationException `UNKNOWN_METHOD` with the message `Invalid method name: '<name>'`.
- A ONEWAY message gets no reply. A REPLY or EXCEPTION sent by the client ends the session (`handler_close`).

If the frame length is 0 or over 64 KiB, only the 4 length bytes are recorded and the session ends with `read_error`. An undecodable message header is recorded without `command`/`message` and also ends with `read_error`. A partial frame is recorded as is. After 32 frames the session ends with `max_frames`. No keyspaces, rings or query results are emulated. Thrift on other ports stays in generic `tcp`.
