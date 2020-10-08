#!/bin/bash
# USAGE:sudo ./autourl.sh <container_name>

container=$1
host_ip=$(docker inspect $container | jq '.[].NetworkSettings.Ports."8080/tcp"[].HostIP')


if [ "$host_ip" == "null" ]
then
	host_ip=localhost
fi

host_ip="${host_ip%\"}"
host_ip="${host_ip#\"}"
echo "IP: $host_ip"

host_port=$(docker inspect $container | jq '.[].NetworkSettings.Ports."8080/tcp"[].HostPort')

if [ "$host_port" == "null" ]
then
	echo "Port unassigned"
else
	host_port="${host_port%\"}"
	host_port="${host_port#\"}"
	echo "Port: $host_port"
	echo "URL is http://$host_ip:$host_port"
fi
