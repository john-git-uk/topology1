#!/bin/bash

ip addr add 10.131.70.250/24 dev eth1
ip link set eth1 up
ip route add default via 10.131.70.254

ip addr add 192.168.250.102/24 dev eth2
ip link set eth2 up