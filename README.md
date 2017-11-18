# Glutton [![Build Status](https://travis-ci.org/mushorg/glutton.svg?branch=master)](https://travis-ci.org/mushorg/glutton)

Setup `go 1.7+`. Install required system packages:
```
apt-get install libnetfilter-queue-dev libpcap-dev iptables-dev
```
To change your SSH server default port (i.e. 5001, see `rules.yaml`) and restart sshd:
```
sed -i 's/[# ]*Port .*/Port 5001/g' /etc/ssh/sshd_config
```
Download glutton, and install dependencies using `glide`:
```
go get github.com/mushorg/glutton
cd $GOPATH/src/github.com/mushorg/glutton/
curl https://glide.sh/get | sh
glide install
glide update
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

Glutton provide SSH and TCP proxy. SSH proxy work as MITM between attacker and server to log every thing in plan text. TCP proxy does not provide facility for logging yet. Examples can be found [here](https://github.com/mushorg/glutton/tree/master/examples). 

