#!/bin/bash
#
#
# I use this to copy paste, not run.
#
#

#ISP 92
terminator --new-tab -e "telnet 192.168.2.247 30166" &
sleep 0.2

## Switches Telnet
#######################################################
#sw1 89
terminator --new-tab -e "telnet 192.168.2.247 30089" &
sleep 0.2

#sw2 90
terminator --new-tab -e "telnet 192.168.2.247 30090" &
sleep 0.2

#sw3 95
terminator --new-tab -e "telnet 192.168.2.247 30095" &
sleep 0.2

#sw4 96
terminator --new-tab -e "telnet 192.168.2.247 30096" &
sleep 0.2

#sw5 97
terminator --new-tab -e "telnet 192.168.2.247 30097" &
sleep 0.2

#sw6 98
terminator --new-tab -e "telnet 192.168.2.247 30098" &
sleep 0.2

#sw7 100
terminator --new-tab -e "telnet 192.168.2.247 30100" &
sleep 0.2

#Old r1 91
#terminator --new-tab -e "telnet 192.168.2.247 30091" &
#sleep 0.2
## Routers Telnet
#######################################################
#r1 165
terminator --new-tab -e "telnet 192.168.2.247 30165" &
sleep 0.2

#r2 94
terminator --new-tab -e "telnet 192.168.2.247 30094" &
sleep 0.2

#r3 99
terminator --new-tab -e "telnet 192.168.2.247 30099" &
sleep 0.2

## Hosts Telnet
#######################################################
#sales1 107
terminator --new-tab -e "telnet 192.168.2.247 30107" &
sleep 0.2

#sales13 101
terminator --new-tab -e "telnet 192.168.2.247 30101" &
sleep 0.2

#guest1 109
terminator --new-tab -e "telnet 192.168.2.247 30109" &
sleep 0.2

#guest13 131
terminator --new-tab -e "telnet 192.168.2.247 30131" &
sleep 0.2


## Servers Telnet
#######################################################
#aaa_server 138
terminator --new-tab -e "telnet 192.168.2.247 30138" &
sleep 0.2


#ldap_server 136
terminator --new-tab -e "telnet 192.168.2.247 30167" &
sleep 0.2

#dns_server 140


#web_server 139


#management_server 136
terminator --new-tab -e "telnet 192.168.2.247 30136" &
sleep 0.2


#free raidus (unused)
terminator --new-tab -e "telnet 192.168.2.247 30168" &
sleep 0.2