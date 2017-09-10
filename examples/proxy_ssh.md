# SSH Proxy

Glutton support for proxying SSH connections. Work as MITM between attacker and SSH server and logs every thing travelling through the secure connection. So attacker will have a real machine with no logging agent inside and it will be very harder for attacker to figerprint the honeypot. Glutton only support integration of one SSH server.

## Integration

Note the IP address and port of destination SSH server and register in Glutton with help of `rules/rules.yaml` file. 
Edit the follwing rules and past it into `rules/rules.yaml`:  

```
  - match: tcp dst port 22 or port 2222 or <any>
    type: conn_handler
    name: proxy_ssh
    target: tcp://<IP Address>:<Port>
```

Every connection on port `22` and `2222` will be forwarded to SSH server at `target` IP address.

Note: Rules are matched against packet from top to bottom so first matching rule will executed. Make sure you have placed the rule at right position. 