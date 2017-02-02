# Glutton [![Build Status](https://travis-ci.org/mushorg/glutton.svg?branch=master)](https://travis-ci.org/mushorg/glutton)

Setup `go 1.7+`. Install required packages -
```
apt-get install libnetfilter-queue-dev libpcap-dev iptables-dev
```
To change your SSH server default port (i.e. 5001)
```
sed -i 's/Port 22/Port 5001/' /etc/ssh/sshd_config
```
Download glutton, and install dependencies using `glide` -
```
go get github.com/mushorg/glutton
mkdir /etc/glutton
cp $GOPATH/src/github.com/mushorg/glutton/rules/rules.yaml /etc/glutton
curl https://glide.sh/get | sh
glide install
glide update
```
Install `glutton` -
```
cd $GOPATH/src/github.com/mushorg/glutton
make
```
To test glutton -
```
gluttonserver -log /tmp/glutton.log
```
