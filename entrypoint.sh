#!/bin/bash

# This file is used as an entrypoint for the docker container

set -e

if [ -z "$MAPPING_PREFIX" ]; then
	echo "Environment variable MAPPING_PREFIX not set"
	exit 1
fi

if [ -z "$MAP_STATIC" ]; then
	echo "Environment variable MAP_STATIC not set"
	exit 1
fi

cfile=/tmp/map646.config

echo "mapping-prefix $MAPPING_PREFIX" > $cfile

#OIFS=IFS
#for entry in $(echo "$MAP_STATIC" | tr -d ";" "$\n"); do
while IFS=';' read -a entry; do
	IPv4=$(echo $entry | cut -d= -f1)
	IPv6=$(echo $entry | cut -d= -f2)
	if [ -z "$IPv4" -o -z "$IPv6" ]; then
		echo "Error on $entry of MAP_STATIC: must be in the form IPv4=IPv6"
		exit 1
	fi
	echo "map-static $IPv4 $IPv6" >> $cfile
done <<< "$MAP_STATIC"

echo Generated config file:
cat $cfile

echo Will run map646
./map646 -c $cfile &
map_process=$!

sleep 2

ip -6 route add $MAPPING_PREFIX/96 dev tun646 || true

while IFS=';' read -a entry; do
	IPv4=$(echo $entry | cut -d= -f1)
	ip route add $IPv4 dev tun646 || true
done <<< "$MAP_STATIC"

wait $!
