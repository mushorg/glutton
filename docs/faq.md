# FAQ

## Is Glutton high-interaction?

No. Glutton sits in the low-interaction range: handlers emulate enough protocol behavior to capture useful probes and payloads, but they're controlled Go implementations, not real services or shells.

## Which protocols are registered?

TCP: SMTP, RDP, SMB, FTP, SIP, RFB/VNC, Telnet, MQTT, iSCSI, BitTorrent, Memcache, Jabber, ADB, MongoDB, HTTP, generic TCP, plus `proxy_tcp` forwarding. UDP: a generic UDP handler.

The HTTP handler also dispatches a handful of nested, payload-driven mini-handlers once a request is parsed:

- Ethereum JSON-RPC
- Hadoop YARN exploit
- Docker Engine API
- Citrix ADC / NetScaler (CVE-2019-19781)
- VMware "hyper/send" attack
- Wallet probes

These nested branches live inside the HTTP handler rather than being registered as separate handler keys, so they're not selectable via a rule `target`.

## Does Spicy parse every protocol?

No. Current grammar files are `http.spicy` and `tcp.spicy`. Spicy is used for selected HTTP parsing and TCP-payload protocol detection only.

## Why does Glutton require Linux?

Glutton is built on Linux-only kernel facilities and tooling like TPROXY, iptables and libpcap. On macOS or Windows you can edit the Go code, but the binary will not redirect traffic, manage iptables, or load the Spicy runtime. Use a Linux VM, container, or remote host for anything beyond static analysis.
