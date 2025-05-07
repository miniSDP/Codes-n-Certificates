#!/bin/bash
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -A INPUT -p tcp -s 192.168.1.4 --dport 8443 -j ACCEPT
