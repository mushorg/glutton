# Glutton [![Build Status](https://travis-ci.org/mushorg/glutton.svg?branch=master)](https://travis-ci.org/mushorg/glutton)

Setup `go 1.7+`. Install required system packages:
```
apt-get install libnetfilter-queue-dev libpcap-dev iptables-dev
```
To change your SSH server default port (i.e. 5001, see `rules.yaml`) and restart sshd:
```
sed -i 's/Port 22/Port 5001/' /etc/ssh/sshd_config
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
bin/server -log /tmp/glutton.log -rules rules/rules.yaml
```
