# Glutton
![Tests](https://github.com/mushorg/glutton/actions/workflows/workflow.yml/badge.svg)
[![GoDoc](https://godoc.org/github.com/mushorg/glutton?status.svg)](https://godoc.org/github.com/mushorg/glutton)

Setup `go 1.17`. Install required system packages:
```
apt-get install gcc libnetfilter-queue-dev libpcap-dev iptables lsof
```

Arch:
```
pacman -S gcc libnetfilter_queue libpcap iptables lsof
```

To change your SSH server default port (i.e. 5001, see `rules.yaml`) and restart sshd:
```
sed -i 's/[# ]*Port .*/Port 5001/g' /etc/ssh/sshd_config
```

Build glutton:
```
make build
```

To run/test glutton:
```
bin/server
```

# Use as Proxy

Glutton provide SSH and a TCP proxy. SSH proxy works as a MITM between attacker and server to log everything in plain text. TCP proxy does not provide facility for logging yet. Examples can be found [here](https://github.com/mushorg/glutton/tree/master/examples).
