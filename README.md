# Glutton
![Tests](https://github.com/mushorg/glutton/actions/workflows/workflow.yml/badge.svg)
[![GoDoc](https://godoc.org/github.com/mushorg/glutton?status.svg)](https://godoc.org/github.com/mushorg/glutton)

Setup `go 1.17`. Install required system packages:
```
apt-get install gcc libpcap-dev iptables
```

Arch:
```
pacman -S gcc libpcap iptables
```

To change your SSH server default port (i.e. 5001, see `rules.yaml`) and restart SSHD:
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
