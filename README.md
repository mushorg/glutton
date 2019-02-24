# Glutton
[![Build Status](https://travis-ci.org/mushorg/glutton.svg?branch=master)](https://travis-ci.org/mushorg/glutton)
[![GoDoc](https://godoc.org/github.com/mushorg/glutton?status.svg)](https://godoc.org/github.com/mushorg/glutton)
[![Coverage Status](https://coveralls.io/repos/github/mushorg/glutton/badge.svg?branch=master)](https://coveralls.io/github/mushorg/glutton?branch=master)

Setup `go 1.11+`. Install required system packages:
```
apt-get install libnetfilter-queue-dev libpcap-dev iptables-dev
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
