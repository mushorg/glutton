# `udp` decoded data

Transport: UDP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of read frames: `direction`, `payload`, `payload_hash`, `truncated`

Catch-all. One datagram per event (capped at 1024 bytes). `truncated` is set when the datagram was longer. The handler does not reply. Datagrams starting with a SIP request or status line are rerouted to `sip`; datagrams with RakNet offline magic are rerouted to `raknet`; APPLICATION 10/12 Kerberos AS-REQ/TGS-REQ are rerouted to `kerberos`; CoAP version-1 GET/POST/PUT/DELETE datagrams are rerouted to `coap`; IKE headers whose length field equals the datagram length (optionally after the 4-byte non-ESP marker) are rerouted to `ike`; Source Engine queries (`ffffffff` + A2S request type) are rerouted to `a2s`; PlayStation DDP request lines (`SRCH`/`WAKEUP`/`LAUNCH * HTTP/1.1`) are rerouted to `ddp`; WS-Discovery SOAP envelopes are rerouted to `wsdiscovery`; KNXnet/IP headers (`06 10`, a request service type, length field equal to the datagram length) are rerouted to `knx`; epoch-0 DTLS ClientHello records are rerouted to `dtls`.
