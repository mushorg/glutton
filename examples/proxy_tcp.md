# TCP Proxy

Glutton provides transport layer proxy to proxy tcp connections.

## Integration

Note the IP address and port of destination TCP server and register in Glutton with help of `rules/rules.yaml` file. 
Edit the follwing rules and past it into `rules/rules.yaml`:  

```
  - match: tcp dst port 6000 or port 7000 or <any>
    type: conn_handler
    name: proxy_tcp
    target: tcp://<IP Address>:<Port>
```

Every connection on port `22` and `2222` will be forwarded to TCP server at `target` IP address.

Note: Rules are matched against packet from top to bottom so first matching rule will executed. Make sure you have placed the rule at right position. 