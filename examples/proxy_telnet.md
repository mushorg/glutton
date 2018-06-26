# TELNET Proxy

Glutton support for proxying TELNET connections. Work as MITM between attacker and TELNET server and logs every thing travelling through the connection. So attacker will have a real machine with no logging agent inside and it will be very harder for attacker to figerprint the honeypot. Glutton only support integration of one TELNET server.

## Integration

Note the IP address and port of destination TELNET server and register in Glutton with help of `rules/rules.yaml` file. 
Edit the follwing rules and past it into `rules/rules.yaml`:  

```
  - match: tcp dst port 23
    type: conn_handler
    name: proxy_telnet
    target: tcp://<IP Address>:<Port>
```

Every connection on port `23` TELNET server at `target` IP address.

Note: Rules are matched against packet from top to bottom so first matching rule will executed. Make sure you have placed the rule at right position. 