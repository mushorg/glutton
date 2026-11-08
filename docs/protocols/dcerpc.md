# `dcerpc` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `dcerpc`, `command`, `call_id`, `interface`, `interface_version`, `opnum`, `target_interface`, `target_interface_version`, `status`, `payload`

Connection-oriented DCE/RPC (MS-RPCE), answered as the Windows endpoint mapper (rpcss) on tcp/135 does. There is no port rule: the catch-all routes a little-endian DCE/RPC v5.0 bind or request (`05 00 0b`/`05 00 00`, data representation `0x10`) to this handler on any port, so tcp/135 and dynamic RPC ports (49664+) are covered. Other bytes on tcp/135 get no reply from the catch-all (`dcerpc` port response, `Silent`), as rpcss drops them.

Each PDU is one frame. `payload` is the whole PDU including the 16-byte header. `dcerpc` is the PDU type (`DCERPC_BIND`, `DCERPC_REQUEST`, `DCERPC_BIND_ACK`, `DCERPC_RESPONSE`, `DCERPC_FAULT`, or `DCERPC_0xNN`). On reads, `command` is the endpoint mapper operation (`ept_lookup`, `ept_map`, `ept_insert`, …) when the request was made on a bound EPM context, and otherwise the PDU type. `call_id` is echoed on the matching write.

| Client sends | Reply (`status`) |
| --- | --- |
| Bind | Bind ack accepting every offered context with the client's transfer syntax, secondary address = the destination port (`"135"`) (`bind_ack`). The read has `interface` / `interface_version` of the first context. |
| `ept_lookup` (opnum 2) or `ept_map` (opnum 3) on the endpoint mapper (`e1af8308-5d1f-11c9-91a4-08002b14a0fa` v3.0) | Response with a nil context handle, zero entries, an empty array sized `max_ents` / `max_towers`, and `EPT_S_NOT_REGISTERED` (`0x16c9a0d6`) (`EPT_S_NOT_REGISTERED`). The read has `target_interface` / `target_interface_version` when the client named one (the `Ifid` of a lookup, the floor-1 interface of a map tower). |
| Other EPM opnum 0–6, or a lookup/map whose stub does not parse | Fault `nca_s_fault_ndr` (`0x6f7`) (`nca_s_fault_ndr`) |
| EPM opnum above 6 | Fault `nca_s_op_rng_error` (`nca_s_op_rng_error`) |
| Request on another bound interface (e.g. IOXIDResolver `ServerAlive2`) | Fault `nca_s_fault_ndr` |
| Request on a context id that was never bound | Fault `nca_s_unknown_if` (`nca_s_unknown_if`) |
| Any other PDU type (alter_context, auth3, …), or bytes that are not a DCE/RPC header | No reply; the read is recorded and the connection closes (`endReason` `handler_close`) |

Faults and responses echo `call_id` and `p_cont_id`. The honeypot never returns an endpoint, so it cannot route a client to a working RPC service. A PDU cut short by the client is recorded with the bytes that arrived (`endReason` `client_close`). Up to 32 PDUs are answered per connection (`endReason` `max_frames` after that).

Older sensors answered every client message on tcp/135 with the same static bind ack (`tcp` event, `status` `dcerpc-bind-ack`), including the `ept_lookup` request that follows the bind; that second bind ack is a handler artifact.
