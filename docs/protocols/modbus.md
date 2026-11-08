# `modbus` decoded data

Transport: TCP. Shared encodings and frame fields are described in [Logging and producers](../logging.md#decoded-data).

**`decoded`:** Array of per-direction frames: `direction`, `command`, `function_code`, `unit_id`, `address`, `quantity`, `device_id_code`, `object_id`, `status`, `payload`

`command` copies `function_code`. Exception writes set `status` `Exception`.

Read Device Identification (FC `0x2B`, MEI `0x0E`) has `function_code` `EncapsulatedInterfaceTransport` and `command` `ReadDeviceIdentification`. `device_id_code` (1 basic, 2 regular, 3 extended, 4 individual) and `object_id` come from the request and are copied onto the reply frame. The reply reports a Modicon M340 (`Schneider Electric`, `BMX P34 2020`, `v2.70`, plus the regular objects 3-6) with conformity level `0x82`. An unknown object id with individual access gets exception `0x02`, and an unknown read code gets `0x03`. The rule routes tcp/502 and tcp/504 to this handler.
