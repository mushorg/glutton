# Glutton [![Build Status](https://travis-ci.org/mushorg/tanner.svg?branch=master)](https://travis-ci.org/mushorg/tanner)

The Glutton server listens on both TCP and UDP port 5000 for new connections. Implement following iptables rules in order to redirect all traffic to port 5000 (tested on Ubuntu 16.04).

First make sure you have installed iptables-persistent and conntrack-tools. During installation select YES for saving your current firewall rules for both ipv4 and ipv6.

```
apt-get install iptables-persistent
apt-get install conntrack
```
To change your SSH server default port (i.e. 5001)
```
sed -i 's/#Port 22/Port 5001/' /etc/ssh/sshd_config
```
Now enable the redirect while leaving out the port you picked for sshd: 
```
iptables -t nat -A PREROUTING -p tcp --dport 1:5000 -j REDIRECT --to-port 5000
iptables -t nat -A PREROUTING -p tcp --dport 5002:65389 -j REDIRECT --to-port 5000  
iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-port 5000  
```
Save the new rules:
```
service iptables-persistent save  
service iptables-persistent reload  
```
In case of error try:  
```
service netfilter-persistent save  
service netfilter-persistent reload
```
Now Glutton server listening on all tcp udp ports of the system except one for SSH 5001.
