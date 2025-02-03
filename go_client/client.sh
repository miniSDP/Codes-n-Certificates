#!/bin/bash

echo "Port scan before SPA"
sudo nmap -sS -p 443 192.168.1.4
echo
echo

read -p "Enter your username: " username

read -s -p "Enter your password: " password
echo

# Concatenate username and password
concat_term="${username}${password}"

# Command for fwknop
command="fwknop -n 192.168.1.4 -a 192.168.1.5 -U $concat_term -R"
echo "Executing: $command"
eval "$command"

sleep 2

echo
echo

echo "Port scan after SPA"
sudo nmap -sS -p 443 192.168.1.4

echo
echo

# File path for Go source file
GO_FILE="client.go"

# Replace username and service in the Go file
read -p "Enter service: " service
sed -i -E "s/(\"username\"[[:space:]]*:[[:space:]]*\")[^\"]*(\")/\1$username\2/" "$GO_FILE"
sed -i -E "s/(\"service\"[[:space:]]*:[[:space:]]*\")[^\"]*(\")/\1$service\2/" "$GO_FILE"

echo
echo

go run "$GO_FILE" 

echo
echo "End"
               
