#!/bin/bash
sudo iptables -F
sudo iptables -I INPUT -i eth0 -p tcp --dport 443 -j DROP
sudo iptables -I INPUT -i eth0 -p tcp --dport 443 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
