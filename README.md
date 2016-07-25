# Glutton [![Build Status](https://travis-ci.org/mushorg/tanner.svg?branch=master)](https://travis-ci.org/mushorg/tanner)
All eating honeypot
===========================================================================================

Glutton server listens for both TCP and UDP at port 5000 in parallel. Implement following iptables rules in order to redirect all traffic to port 5000.
Below steps are tested on Ubuntu 16.04.

First make sure you have installed iptables-persistent. During installation select YES for saving your current firewall rules for both ipv4 and ipv6.
```
apt-get install iptables-persistent
```
To change your SSH server default port to 5001.  
```
sed -i 's/Port 22/Port 5001/' /etc/ssh/sshd_config

iptables -t nat -A PREROUTING -p tcp --dport 1:5000 -j REDIRECT --to-port 5000
iptables -t nat -A PREROUTING -p tcp --dport 5002:65389 -j REDIRECT --to-port 5000  
iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-port 5000  
service iptables-persistent save  
service iptables-persistent reload  
```
In case of error try:  
```
service netfilter-persistent save  
service netfilter-persistent reload
```
Now Glutton server listening on all tcp udp ports of the system except one for SSH 5001.




