# Glutton [![Build Status](https://travis-ci.org/mushorg/tanner.svg?branch=master)](https://travis-ci.org/mushorg/tanner)
All eating honeypot
===========================================================================================

Glutton server listens for both TCP and UDP at port 5000 in parallel. Implement following iptables rules in order to redirect all traffic to port 5000.
Below steps are tested on Ubuntu 16.04.

First make sure you have installed iptables-persistent. During installation select YES for saving your current firewall rules for both ipv4 and ipv6.

$ apt-get install iptables-persistent

To deal with your openssh-server first change your SSH default port.  
$ sed -i 's/Port 22/Port 5001/' /etc/ssh/sshd_config  

$ sysctl -w net.ipv4.conf.eth0.route_localnet=1  
$ iptables -A PREROUTING -t nat -p tcp --dport 22 -j REDIRECT --to-port 5001  
$ iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-port 5000  
$ iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-port 5000  

$ sudo service iptables-persistent save  
$ sudo service iptables-persistent reload  

In case of error try:  
$ sudo service netfilter-persistent save  
$ sudo service netfilter-persistent reload  
  
Now Glutton server listening on all tcp udp ports of the system except one for SSH.




