import ipaddress
import os
import logging
import re
from pathlib import Path
from project_globals import GLOBALS
from typing import Optional, List, Dict
from convert import cidr_to_wildmask, ipv4_netid, cidr_to_netmask
from genie.conf import Genie
from genie.libs.parser.utils import get_parser
from genie.testbed import load
LOGGER = logging.getLogger('my_logger')

def cisco_stp_vlan_config(node):
	if node is None:
		LOGGER.error(f"Node is None in cisco_stp_vlan_config")
		return
	if node.machine_data.device_type != "cisco_ios" and node.machine_data.device_type != "cisco_xe":
		LOGGER.error(f"Node {node.hostname} is not a cisco device")
		return
	if node.machine_data.category != "multilayer" and node.machine_data.category != "switch":
		LOGGER.error(f"Node {node.hostname} is not multilayer or switch")
		return
	if node.topology_a_part_of is None:
		LOGGER.error(f"Node {node.hostname} is not part of a topology")
		return
	if node.get_access_segment() is None:
		LOGGER.error(f"Node {node.hostname} is not part of a access segment")
		return
	if len(node.get_access_segment().vlans) == 0:
		LOGGER.error(f"Node {node.get_access_segment().name} has no vlans")
		return
	############################################
	LOGGER.info(f"Generating stp vlan config for {node.hostname}")
	node.stp_vlan_config_commands = []
	node.stp_vlan_config_commands += ['spanning-tree mode rapid-pvst']
	for vlan in node.get_access_segment().vlans:
		node.stp_vlan_config_commands += [
			'vlan ' + str(vlan.number),
			'name ' + vlan.name,
			'exit'
		]
		if vlan.fhrp0_priority is None:
			continue
		if(vlan.fhrp0_priority.node_a_part_of.hostname == node.hostname):
			node.stp_vlan_config_commands += [
				'spanning-tree vlan ' + str(vlan.number) + ' priority ' + str(4096),
				'spanning-tree vlan ' + str(vlan.number) + ' root primary'
			]
		else:
			node.stp_vlan_config_commands += [
				'spanning-tree vlan ' + str(vlan.number) + ' priority ' + str(0),
				'spanning-tree vlan ' + str(vlan.number) + ' root secondary'
			]

	if len(node.stp_vlan_config_commands) == 0:
		return

def cisco_radius_client_config(node):
	"""
	Generates a radius client config for the node
	"""
	LOGGER.debug(f"Generating radius client config for {node.hostname}")
	if node is None:
		LOGGER.error(f"Node is None in generate_radius_client_config")
		return
	topology = node.topology_a_part_of
	if topology is None:
		LOGGER.error(f"Topology is None in generate_radius_client_config")
		return
	# TODO: Hardcoded
	radius_server_1 = topology.get_node('radius-server-1')
	if radius_server_1 is None:
		LOGGER.error(f"Radius server 1 is None in generate_radius_client_config")
		return
	#radius_ip = radius_server_1.get_interface('ethernet', 'eth3').ipv4_address
	
	# TODO: Hardcoded
	radius_ip = None
	for acc in topology.access_segments:
		if acc.name != "main":
			continue
		for vlan in acc.vlans:
			if vlan.name != "management":
				continue
			for interfacex in range (radius_server_1.get_interface_count()):
				interface = radius_server_1.get_interface_no(interfacex)
				if not interface.ipv4_address:
					continue
				if interface.ipv4_address in vlan.ipv4_netid:
					radius_ip = interface.ipv4_address
					break
			if radius_ip is not None:
				break
		if radius_ip is None:
			break
			
	######################
	if node.machine_data.device_type == 'cisco_ios' or node.machine_data.device_type == 'cisco_xe':
		node.radius_client_config = [
			'aaa new-model',
			'ip radius source-interface Loopback0',

			'radius server radius-server-1',
			f'address ipv4 {radius_ip} auth-port 1812 acct-port 1813',
			'key r1radiuskey', # TODO: This should not be R!
			'exit',
			'aaa group server radius aaa_group',
			'server name radius-server-1',
			'exit',

			'aaa authentication login vty_method group aaa_group',
			'aaa authorization exec default group aaa_group',

			'radius-server attribute 32 include-in-access-req format "Net-Cisco-B@4]-%h"',

			'line vty 0 4',
			'login auth vty_method',
		]

def cisco_ntp_config(node):
	if node is None:
		LOGGER.error(f"Node is None in cisco_stp_vlan_config")
		return
	if node.machine_data.device_type != "cisco_ios" and node.machine_data.device_type != "cisco_xe":
		LOGGER.error(f"Node {node.hostname} is not a cisco device")
		return
	if node.topology_a_part_of is None:
		LOGGER.error(f"Node {node.hostname} is not part of a topology")
		return
	############################################

	node.ntp_config_commands += [
		"clock timezone GMT 0",
		"clock summer-time BST recurring last Sun Mar 1:00 last Sun Oct 2:00",
		"ntp authenticate",
		f"ntp authentication-key 1 md5 {node.topology_a_part_of.ntp_password}",
		"ntp trusted-key 1",
		f"ntp server {node.topology_a_part_of.ntp_public}",
	]
	# Check if the master
	master = False
	for interfacei in range(node.get_interface_count()):
		interface = node.get_interface_no(interfacei)
		if (id(interface) == id(node.topology_a_part_of.ntp_master)):
			node.ntp_config_commands += [
				f'ntp master',
			]
			master = True
			break
	if not master:

		if(node.topology_a_part_of.ntp_master is not None):

			node.ntp_config_commands += [
				f'ntp server {node.topology_a_part_of.ntp_master.ipv4_address} key 1 prefer',
			]

	node.ntp_config_commands += [	
		"ntp update-calendar"
	]
	
	node.ntp_config_commands += [
			f'ntp source {node.get_identity_interface().interface_type} {node.get_identity_interface().name}'
			]
	
	if len(node.ntp_config_commands) == 0:
		return

def cisco_wan_config(node):
	# TODO: Make this part of data not hardcoded
	###############################################
	###############################################
	if(node.machine_data.device_type != "cisco_ios" and node.machine_data.device_type != "cisco_xe"):
		LOGGER.warning(f"Node {node.hostname} is not a cisco device")
		return
	if(node.machine_data.category != "router"):
		LOGGER.info(f"Node {node.hostname} is not a router")
		return
	LOGGER.info(f"Generating wan config for {node.hostname}")
	
	# Find the interface that connects to ISP
	
	if(node.get_wan_interface() is None):
		LOGGER.debug(f"{node.hostname} has no wan interface, skipping wan config generation")
		return
	# TODO: hardcoded subnetting
	node.wan_config_commands = []
	node.wan_config_commands += [
		f'ip access-list extended NAT',
		#f'10 permit ip 10.133.0.0 {cidr_to_wildmask(16)} {ipv4_netid(node.topology_a_part_of.exit_interface_main.ipv4_address,24)} {cidr_to_wildmask(24)}',
		f'20 deny ip 10.133.0.0 {cidr_to_wildmask(16)} 10.133.0.0 {cidr_to_wildmask(16)}',
		f'30 permit ip 10.133.0.0 {cidr_to_wildmask(16)} any',
		f'10000 deny ip any any',
		"exit",
		f'ip nat inside source list NAT interface {node.get_wan_interface().interface_type} {node.get_wan_interface().name} overload'
	]
	
	for interfacei in range(node.get_interface_count()):
		interface = node.get_interface_no(interfacei)
		if(interface.ipv4_address is None):
			continue
		if(interface.interface_type == "loopback"):
			continue
		if(interface.interface_type == "tunnel"):
			continue
		if(interface == node.get_wan_interface()):
			node.wan_config_commands += [
				f'interface {interface.interface_type} {interface.name}',
				f'ip nat outside',
				f'exit',
			]
		else:
			node.wan_config_commands += [
				f'interface {interface.interface_type} {interface.name}',
				f'ip nat inside',
				f'exit',
			]
	
	node.wan_config_commands += [
		"crypto isakmp policy 10",
		"en aes 256",
		"auth pre-share",
		"group 14",
		"lifetime 3600",
		"exit",
	]
	# TODO: Make this part of data not hardcoded
	if node.hostname == "r1":
		node.wan_config_commands += [
			f"crypto isakmp key vpnsecretkey13 address {node.topology_a_part_of.get_node("r3").get_wan_interface().ipv4_address}",
		]
	if node.hostname == "r2":
		node.wan_config_commands += [
			f"crypto isakmp key vpnsecretkey23 address {node.topology_a_part_of.get_node("r3").get_wan_interface().ipv4_address}",
		]
	if node.hostname == "r3":
		node.wan_config_commands += [
			f"crypto isakmp key vpnsecretkey13 address {node.topology_a_part_of.get_node("r1").get_wan_interface().ipv4_address}",
			f"crypto isakmp key vpnsecretkey23 address {node.topology_a_part_of.get_node("r2").get_wan_interface().ipv4_address}",
		]

	node.wan_config_commands += [
		"crypto ipsec transform-set TunnelCipher esp-gcm 256",
		"mode tunnel",
		"exit",
	]

	node.wan_config_commands += [
		"ip access-list extended vpn_traff",
		f"deny ip any 192.168.2.0 {cidr_to_wildmask(24)}",
		f"permit ip 10.133.0.0 {cidr_to_wildmask(16)} 10.133.0.0 {cidr_to_wildmask(16)}",
		"exit",
		"crypto ipsec profile VPNPROFILE",
		"set transform-set TunnelCipher",
	]

	for tunneli in range (node.get_interface_count()):
		tunnel = node.get_interface_no(tunneli)

		if tunnel.interface_type != "tunnel":
			continue
		# Find ospf neighbour and validate data
		ospf_neighbour=None
		if(tunnel.ipv4_address is None):
			LOGGER.critical(f"{node.hostname} - {tunnel.name} has no ipv4 address, cannot configure VPN, skipping node config...")
			return
		if(tunnel.ipv4_cidr is None):
			LOGGER.critical(f"{node.hostname} - {tunnel.name} has no ipv4 cidr, cannot configure VPN, skipping node config...")
			return
		if(tunnel.tunnel_destination is None):
			LOGGER.critical(f"{node.hostname} - {tunnel.name} has no tunnel destination, cannot configure VPN, skipping node config...")
			return
		for neighi in range(tunnel.tunnel_destination.node_a_part_of.get_interface_count()):
			neigh = tunnel.tunnel_destination.node_a_part_of.get_interface_no(neighi)
			if(neigh.interface_type == "loopback" and neigh.name == "0"):
				if(neigh.ipv4_address is None):
					LOGGER.critical(f"{neigh.interface_type} {neigh.name} has no ipv4 address, cannot configure VPN, skipping node config...")
					return
				if(neigh.ipv4_cidr is None):
					LOGGER.critical(f"{neigh.interface_type} {neigh.name} has no ipv4 cidr, cannot configure VPN, skipping node config...")
					return
				ospf_neighbour=neigh.ipv4_address

		node.wan_config_commands += [
			f"interface {tunnel.interface_type} {tunnel.name}",
			f"ip address {tunnel.ipv4_address} {cidr_to_netmask(tunnel.ipv4_cidr)}",
			f"tunnel source {node.get_wan_interface().ipv4_address}",
			"tunnel mode ipsec ipv4",
			f"tunnel destination {tunnel.tunnel_destination.ipv4_address}",
			"tunnel protection ipsec profile VPNPROFILE",
			"ip ospf network point-to-point",
			"no shutdown",
			"exit",
			# Add static routes to prevent advertisments of VPN taking precidense
			f"ip route {tunnel.tunnel_destination.ipv4_address} 255.255.255.255 {node.get_wan_interface().neighbour.ipv4_address}",
			"router ospf 1",
			f"neighbor {ospf_neighbour}",
			"exit",
		]

	if len(node.wan_config_commands) == 0:
		return

def cisco_ospf_static_base_config(node):
		if(node.machine_data.device_type != "cisco_ios" and node.machine_data.device_type != "cisco_xe"):
			LOGGER.error(f"Device type {node.machine_data.device_type} is not supported for OSPF or static routing config generation, manual config required")
			return
		if(node.machine_data.category != "multilayer" and node.machine_data.category != "router"):
			LOGGER.error(f"Device category {node.machine_data.category} is not supported for OSPF or static routing config generation, manual config required")
			return

		LOGGER.info(f"Generating ospf static base config for {node.hostname}")
		
		if(node.hostname == "ISP"):
			LOGGER.error(f"ISP node is not currently supported for OSPF or static routing config generation, manual config required")
			return
		node.ospf_static_base_config_commands = []
		
		if node.get_wan_interface() is not None:
			node.ospf_static_base_config_commands += [
				f'ip route 0.0.0.0 0.0.0.0 {str(node.get_wan_interface().neighbour.ipv4_address)}'
			]
		
		ospf_commands=[]
		if node.machine_data.category == "multilayer":
			ospf_commands += ['ip routing']
		ospf_commands += ['router ospf 1']
		ospf_commands += ['auto-cost reference-bandwidth 100000']
		if node.get_wan_interface() is not None:
			ospf_commands += ["default-information originate"]
		for interfacei in range(node.get_interface_count()):
			interface = node.get_interface_no(interfacei)
			if interface.ospf_participant:
				if interface.ipv4_address is None:
					LOGGER.critical(f"Interface {interface.name} has no ip address, skipping ospf static base config generation")
					return
				# TODO: Shouldnt vlan 30 be a participant?
				if (interface.interface_type !="vlan") and (interface.interface_type != "loopback"):
					if interface.neighbour is None:
						LOGGER.critical(f"Interface {interface.name} has no neighbour, skipping ospf static base config generation")
						return
				# If this interface has an ip address
				# Advertise the network
				ospf_commands += [f'network {str(ipv4_netid(interface.ipv4_address,interface.ipv4_cidr))} {str(cidr_to_wildmask(interface.ipv4_cidr))} area 0']
			# If a layer 3 interface check if passive interface
			if interface.ospf_passive and interface.ipv4_address is not None:
				ospf_commands += [f'passive-interface {interface.interface_type} {interface.name}']
		
		ospf = False
		for command in ospf_commands:
			if command.startswith("network"):
				ospf = True
		if ospf == False:
			ospf_commands = []
			LOGGER.debug("no interfaces participating in ospf, no config required")
		node.ospf_static_base_config_commands += ospf_commands

		if len(node.ospf_static_base_config_commands) == 0:
			return

def cisco_fhrp_config(node):
	if(node.machine_data.device_type != "cisco_ios" and node.machine_data.device_type != "cisco_xe"):
		LOGGER.error(f"FHRP not supported for {node.machine_data.device_type}")
		return
	if(node.machine_data.category != "multilayer"):
		LOGGER.error(f'FHRP not supported for {node.machine_data.category} devices')
		return
	if(node.get_access_segment() is None):
		LOGGER.debug(f"{node.hostname} not part of FHRP system.")
		return
	LOGGER.info(f"Generating fhrp config for {node.hostname}")
	
	# TODO: Fix this hack
	if node.hostname != 'sw3' and node.hostname != 'sw4':
		return

	# For each node interfaces
	for interfacei in range(node.get_interface_count()):
		interface = node.get_interface_no(interfacei)

		# That is a SVI
		if(interface.interface_type != "vlan"):
			continue
		# Get the vlan from interface name
		vlan = node.get_access_segment().get_vlan_nom(int(interface.name))
		if(vlan == None):
			LOGGER.error(f"vlan {interface.name} not found for {node.hostname}")
			return
		# If the vlan has no fhrp0_ipv4_address defined then skip
		if(vlan.fhrp0_ipv4_address == None):
			continue
		node.fhrp_config_commands += [
			f'interface {interface.interface_type} {interface.name}',
			'standby 0 ip '+str(vlan.fhrp0_ipv4_address),
			'standby 0 preempt delay rel 60',
			'standby 0 timers msec 200 msec 650',
		]
		# If this node interface is the priority
		if(vlan.fhrp0_priority.node_a_part_of.hostname == node.hostname):
			node.fhrp_config_commands += ['standby 0 priority 200']
		else:
			node.fhrp_config_commands += ['standby 0 priority 111']

		if len(node.fhrp_config_commands) == 0:
			return

def cisco_dhcp_config(node):
	# TODO: Make this part of data not hardcoded
	###############################################
	dhcp_server=None
	if(node.hostname == "sw3"):
		dhcp_server="sw3"
	if(node.hostname == "r3"):
		dhcp_server="r3"
	dhcp_helper=None
	if(node.hostname == "sw4"):
		dhcp_helper=node.topology_a_part_of.get_node("sw3").get_interface("loopback","0")
	###############################################
	if(node.machine_data.device_type != "cisco_ios" and node.machine_data.device_type != "cisco_xe"):
		LOGGER.error(f"DHCP not supported for {node.machine_data.device_type}")
		return
	if(node.machine_data.category != "multilayer" and node.machine_data.category != "router"):
		LOGGER.error(f'DHCP not supported for {node.machine_data.category} devices')
		return

	LOGGER.info(f"Generating dhcp config for {node.hostname}")				
	if(node.hostname == dhcp_server):
		for vlan in node.get_access_segment().vlans:
			if (vlan.dhcp_exclusion_start is None) or (vlan.dhcp_exclusion_end is None):
				continue
			if len(vlan.dhcp_exclusion_start) == 0:
				continue
			LOGGER.debug(f"Generating dhcp config for {node.hostname} working on vlan {vlan.name}")

			if(len(vlan.dhcp_exclusion_start) != len(vlan.dhcp_exclusion_end)):
				LOGGER.critical(f"DHCP exclusion start and end do not match for vlan {vlan.name}")
				return

			for exclusion in range(len(vlan.dhcp_exclusion_start)):
				node.dhcp_config_commands += [f'ip dhcp excluded-address {str(vlan.dhcp_exclusion_start[exclusion])} {str(vlan.dhcp_exclusion_end[exclusion])}']
			if(vlan.fhrp0_ipv4_address is not None):
				gateway = vlan.fhrp0_ipv4_address
			else:
				if(vlan.default_gateway is None):
					LOGGER.critical(f"default gateway not set for vlan {vlan.name}")
					continue
				gateway = vlan.default_gateway.ipv4_address
			node.dhcp_config_commands += [
				'ip dhcp pool '+str(vlan.number),
				'network '+str(vlan.ipv4_netid)+' /'+str(vlan.ipv4_cidr),
				'default-router '+str(gateway),
				'domain-name '+node.topology_a_part_of.domain_name_a+'.'+node.topology_a_part_of.domain_name_b,
				# TODO: Add dns servers
				'dns-server '+str(node.topology_a_part_of.dns_private[0].ipv4_address),
				'exit'
			]
	elif(dhcp_helper is not None):
		for interfacei in range(node.get_interface_count()):
			interface = node.get_interface_no(interfacei)

			if(interface.ipv4_address is None):
				continue
			node.dhcp_config_commands += [f"interface {interface.interface_type} {interface.name}"]
			if node.machine_data.device_type == "cisco_xe":
				node.dhcp_config_commands += [f"ip helper-address {dhcp_helper.ipv4_address}"]
			elif node.machine_data.device_type == "cisco_ios":
				node.dhcp_config_commands += [f"ip dhcp helper address {dhcp_helper.ipv4_address}"]

def cisco_interfaces_config(node):
	topology = node.topology_a_part_of
	LOGGER.info(f"Generating interfaces config for {node.hostname}")
	if node.machine_data.device_type == "cisco_ios" or node.machine_data.device_type == "cisco_xe":
		node.interface_config_commands = []
					
		for index_a in range (node.get_interface_count()):
			interface = node.get_interface_no(index_a)
			LOGGER.debug(f"Configuring interface {interface.interface_type} {interface.name}")
			# Is it a port channel?
			if len(interface.interfaces) > 0:
				# Go into members and set the channel group
				first=True
				interface_group=""
				for member in interface.interfaces:
					if first:
						first=False
					else:
						interface_group  += ","
					interface_group += f"{member.interface_type} {member.name}"
				node.interface_config_commands += [
				'interface r '+interface_group,
				'channel-group '+str(interface.interfaces[0].channel_group)+" mode active",
				'no shutdown'
				]
			node.interface_config_commands += [f"interface {interface.interface_type} {interface.name}"]
			# Is it a subinterface?
			# If it contains a period, it's a subinterface
			if interface.name.find(".") > 0:
				if node.get_access_segment() is None:
					LOGGER.error(f"Subinterface assigned node {node.hostname} has no access segment, skipping interface config generation")
					return
				# split the interface name on the period and get the 2nd part
				vlan = interface.name.split(".")[1]
				node.interface_config_commands += [f"encapsulation dot1Q {vlan}"]
			# Does it have an ip address?
			if interface.ipv4_address:
				# Is the machine multilayer?
				# It is not applicable to "vlan" interfaces
				if node.machine_data.category == "multilayer" and (interface.interface_type != "vlan") and (interface.interface_type != "loopback"):
					node.interface_config_commands += ["no switchport"]
				temp_network=ipaddress.IPv4Network(f"0.0.0.0/{interface.ipv4_cidr}")
				node.interface_config_commands += [
					'ip address '+str(interface.ipv4_address)+' '+str(temp_network.netmask),
					'no shutdown'
				]
			else:
				# Does it have vlans?
				if interface.vlans:
					if node.get_access_segment is None:
						LOGGER.error(f"VLAN assigned node {node.hostname} has no access segment, skipping interface config generation")
						return
					# Is it a trunk?
					if interface.trunk:
						allowed_vlans = ""
						first=True
						for vlan in interface.vlans:
							if first:
								first=False
							else:
								allowed_vlans+=(",")
							allowed_vlans+=str(vlan.number)
						node.interface_config_commands += [
							"switchport trunk encapsulation dot1q",
							"switchport mode trunk",
							"switchport trunk native vlan 933",
							'switchport trunk allowed vlan '+allowed_vlans
						]
					else:
						node.interface_config_commands += [
							"switchport mode access",
							"switchport access vlan "+str(interface.vlans[0].number)
						]
					node.interface_config_commands += ["switchport nonegotiate"]
				node.interface_config_commands += ["no shutdown"]
					
		
		if len(node.interface_config_commands) == 0:
			return

def cisco_validate_layer_1_genie(node):
	""" This function will validate the interfaces configured in the _data files exist on the device """
	import subprocess

	LOGGER.info(f"Validating interfaces config for {node.hostname}")
	
	if (node.machine_data.device_type != 'cisco_ios'
	and node.machine_data.device_type != 'cisco_xe'):
		return
	
	# Load your testbed YAML file for device information
	node.topology_a_part_of.make_genie_yaml()
	testbed = load(GLOBALS.testbed_path)

	# Connect to the device
	device = testbed.devices[node.hostname]
	
	subprocess.run(f'ssh-keygen -f "~/.ssh/known_hosts" -R "{(str)(node.oob_interface.ipv4_address)}"', shell=True)
	try:
		device.connect()
	except Exception as e:
		LOGGER.error(f"Failed to connect to {node.hostname}: {e}")
		return

	# Send command and parse
	genie_output = device.parse('show ip interface brief')

	# For each interface
	for index_a in range (node.get_interface_count()):
		interface = node.get_interface_no(index_a)

		# Skip interfaces that are not physical
		if (interface.interface_type == "bridge"
		or interface.interface_type == "subinterface"
		or interface.interface_type == "loopback"
		or interface.interface_type == "tunnel"
		or interface.interface_type == "vlan"):
			continue

		# Check if the interface is in the output
		found = False
		for interface_name, interface_details in genie_output["interface"].items():
			if interface_name.lower() == f'{interface.interface_type}{interface.name}'.lower():
				found = True
				break
		if not found:
			LOGGER.error(f"Interface {interface.name} not found on {node.hostname}")
			return
	LOGGER.info(f"Interfaces on {node.hostname} validated")
	device.disconnect()
	return

def test_apply_interfaces_config_netmiko(node):
	'''
	! This function is in testing and should not be considered reliable. !
	Apply the config commands for interface configuration to a node.
	'''

	if node.machine_data.device_type == 'cisco_ios' or node.machine_data.device_type == 'cisco_xe':
		device_type = node.machine_data.device_type
	else:
		return
	LOGGER.info(f"Applying interfaces config for {node.hostname}")

	# device data for Netmiko
	device = {
			'device_type': device_type, 
			'host': str(node.oob_interface.ipv4_address), 
			'username': node.local_user,
			'password': node.local_password,
			'secret': node.local_password, 
			'port': 22,
			'verbose': True,
			'conn_timeout': 30,
		}
	# Connect
	LOGGER.info(f"Connecting to {node.hostname} with device type {device_type}")
	try:
		connection = ConnectHandler(**device)
	except Exception as e:
		LOGGER.error(f"Error connecting to {node.hostname} with netmiko: {e}")
		return
	LOGGER.info(f"Successfully connected to {node.hostname} with netmiko")

	
	output = connection.send_config_set(node.interface_config_commands)
	
	# Send the commands to file for review
	out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "logs" / "netmiko"
	out_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(out_path,node.hostname+'_interfaces.log'), 'w') as f:
		print(output, file=f)
	
	connection.disconnect()
	LOGGER.info(f"Successfully disconnected from {node.hostname}")

def cisco_ssh_stub(node):
	if(node.machine_data is None):
		LOGGER.warning(f"Node {node.hostname} has no machine data, skipping ssh stub config generation")
		return
	if(node.oob_interface is None):
		LOGGER.warning(f"Node {node.hostname} has no oob interface, skipping ssh stub config generation")
		return
	if(node.local_user is None):
		LOGGER.warning(f"Node {node.hostname} has no local username, skipping ssh stub config generation")
		return
	if(node.local_password is None):
		LOGGER.warning(f"Node {node.hostname} has no local password, skipping ssh stub config generation")
		return
	if(node.machine_data.device_type != 'cisco_ios' and node.machine_data.device_type != 'cisco_xe'):
		return
	node.ssh_stub_config_commands = []
	print(f"Generating SSH stub config for {node.hostname}")
	#node.ssh_stub_config_commands.append(f'conf t')

	node.ssh_stub_config_commands.append(f"hostname {node.hostname}")
	node.ssh_stub_config_commands.append(f"username {node.local_user} privilege 15 secret {node.local_password}")
	node.ssh_stub_config_commands.append("service password-encryption")
	if(node.machine_data.device_type == 'cisco_xe'):
		if(node.domain_override is None):
			node.ssh_stub_config_commands.append(f"ip domain name {node.topology_a_part_of.domain_name_a}.{node.topology_a_part_of.domain_name_b}")
		else:
			node.ssh_stub_config_commands.append(f"ip domain name {node.domain_override}")
	else:
		if(node.domain_override is None):
			node.ssh_stub_config_commands.append(f"ip domain-name {node.topology_a_part_of.domain_name_a}.{node.topology_a_part_of.domain_name_b}")
		else:
			node.ssh_stub_config_commands.append(f"ip domain-name {node.domain_override}")
	node.ssh_stub_config_commands.append("crypto key generate rsa modulus 2048 label ssh")
	node.ssh_stub_config_commands.append("ip ssh version 2")

	node.ssh_stub_config_commands.append(f"interface {node.oob_interface.interface_type} {node.oob_interface.name}")
	# What if it is an etherchannel or subinterface?
	if(len(node.oob_interface.vlans) != 0):
		LOGGER.error(f"Vlans are not supported for oob interface {node.oob_interface.interface_type} {node.oob_interface.name} on {node.hostname}")
		return
	if(len(node.oob_interface.interfaces) != 0):
		LOGGER.error(f"Port-channel groups are currently unsupported for oob interface {node.oob_interface.interface_type} {node.oob_interface.name} on {node.hostname}")
		return
	if node.machine_data.category == "multilayer" and (node.oob_interface.interface_type == "vlan") and (node.oob_interface.interface_type == "loop"):
		node.ssh_stub_config_commands.append("no switchport")

	temp_network=ipaddress.IPv4Network(f"0.0.0.0/{node.oob_interface.ipv4_cidr}")
	node.ssh_stub_config_commands.append(f'ip address {node.oob_interface.ipv4_address} {temp_network.netmask}')
	node.ssh_stub_config_commands.append("no shutdown")
	node.ssh_stub_config_commands.append("exit")

	node.ssh_stub_config_commands.append("aaa new-model")
	node.ssh_stub_config_commands.append("aaa authentication login default local")
	node.ssh_stub_config_commands.append("aaa authorization exec default local")
	node.ssh_stub_config_commands.append("no enable password")
	node.ssh_stub_config_commands.append("no enable secret")
	node.ssh_stub_config_commands.append("line vty 0 4")
	#node.ssh_stub_config_commands.append("login local") # Not applicable with aaa new-model
	node.ssh_stub_config_commands.append("transport input ssh")
	node.ssh_stub_config_commands.append("privilege level 1")
	node.ssh_stub_config_commands.append("exec-timeout 0 0")
	node.ssh_stub_config_commands.append("line console 0")
	node.ssh_stub_config_commands.append("exec-timeout 0 0")
	node.ssh_stub_config_commands.append("exit")
	if(len(node.topology_a_part_of.dns_private) != 0):
		node.ssh_stub_config_commands.append(f'ip name-server {node.topology_a_part_of.dns_private[0].ipv4_address}')
	if node.machine_data.device_type == 'cisco_xe':
		node.ssh_stub_config_commands.append("ip cef")
		node.ssh_stub_config_commands.append("ip domain lookup")
	else:
		node.ssh_stub_config_commands.append("ip domain-lookup")

	
	if len(node.ssh_stub_config_commands) == 0:
		return

def cisco_export_config_files(node):
	#region docstring
	'''
	Outputs the commands that have been generated to text files. Uses the 'output' directory
	located in the project root directory. Each node will have a subdirectory and a file
	with the nodes name followed by '_complete'. This file contains all the commands.
	'''
	#endregion

	if node.machine_data.device_type != 'cisco_xe' and node.machine_data.device_type != 'cisco_ios':
		return
	if len(node.ssh_stub_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_stub.txt'), 'w') as f:
			for command in node.ssh_stub_config_commands:
				print(command, file=f)
	if len(node.interface_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_interface.txt'), 'w') as f:
			for command in node.interface_config_commands:
				print(command, file=f)
	if len(node.ospf_static_base_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_base_routing.txt'), 'w') as f:
			for command in node.ospf_static_base_config_commands:
				print(command, file=f)
	if len(node.wan_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_wan.txt'), 'w') as f:
			for command in node.wan_config_commands:
				print(command, file=f)
	if len(node.stp_vlan_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_stp_vlans.txt'), 'w') as f:
			for command in node.stp_vlan_config_commands:
				print(command, file=f)
	if len(node.fhrp_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_fhrp.txt'), 'w') as f:
			for command in node.fhrp_config_commands:
				print(command, file=f)
	if len(node.dhcp_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_dhcp.txt'), 'w') as f:
			for command in node.dhcp_config_commands:
				print(command, file=f)
	if len(node.ntp_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_ntp.txt'), 'w') as f:
			for command in node.ntp_config_commands:
				print(command, file=f)
	if len(node.radius_client_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_radius_client.txt'), 'w') as f:
			for command in node.radius_client_commands:
				print(command, file=f)
	if len(node.pki_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_pki.txt'), 'w') as f:
			for command in node.pki_config_commands:
				print(command, file=f)
	if len(node.additional_config_commands) > 0:
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_additional.txt'), 'w') as f:
			for command in node.additional_config_commands:
				print(command, file=f)

	out_path = Path(GLOBALS.app_path).parent.resolve() / "output" 
	out_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(out_path,node.hostname+'_complete.txt'), 'w') as f:
		if len(node.ssh_stub_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.ssh_stub_config_commands:
				print(command, file=f)
		if len(node.interface_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.interface_config_commands:
				print(command, file=f)
		if len(node.ospf_static_base_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.ospf_static_base_config_commands:
				print(command, file=f)
		if len(node.ntp_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.ntp_config_commands:
				print(command, file=f)
		if len(node.stp_vlan_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.stp_vlan_config_commands:
				print(command, file=f)
		if len(node.wan_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.wan_config_commands:
				print(command, file=f)
		if len(node.radius_client_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.radius_client_commands:
				print(command, file=f)
		if len(node.fhrp_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.fhrp_config_commands:
				print(command, file=f)
		if len(node.dhcp_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.dhcp_config_commands:
				print(command, file=f)
		if len(node.pki_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.pki_config_commands:
				print(command, file=f)
		if len(node.additional_config_commands) != 0:
			print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!', file=f)
			for command in node.additional_config_commands:
				print(command, file=f)

def cisco_additional_config(node):
	'''
	Searches for a node member function called 'additional_config_commands'
	then calls it.
	'''
	if len(node.additional_config_commands) < 1:
		return

	# Send the commands to file for review
	out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
	out_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(out_path,'additional_config.txt'), 'w') as f:
		for command in node.additional_config_commands:
			print(command, file=f)

def cisco_replace_ethernet_with_gigabit(node):
	'''This is a lab debug function that simplifies the swapping of router images for rapid prototyping.'''
	from node import Node
	replace_list_ethernet_with_gigabit(node.ssh_stub_config_commands)
	replace_list_ethernet_with_gigabit(node.interface_config_commands)
	replace_list_ethernet_with_gigabit(node.stp_vlan_config_commands)
	replace_list_ethernet_with_gigabit(node.fhrp_config_commands)
	replace_list_ethernet_with_gigabit(node.ospf_static_base_config_commands)
	replace_list_ethernet_with_gigabit(node.dhcp_config_commands)
	replace_list_ethernet_with_gigabit(node.wan_config_commands)
	replace_list_ethernet_with_gigabit(node.ntp_config_commands)
	replace_list_ethernet_with_gigabit(node.radius_client_commands)
	replace_list_ethernet_with_gigabit(node.additional_config_commands)

def replace_list_ethernet_with_gigabit(commands_list):
	'''This is a lab debug function that simplifies the swapping of router images for rapid prototyping.'''
	for i, command in enumerate(commands_list):
		command = command.replace('ethernet 0/0', 'gigabit 1')
		command = command.replace('ethernet 0/1', 'gigabit 2')
		command = command.replace('ethernet 0/2', 'gigabit 3')
		command = command.replace('ethernet 0/3', 'gigabit 4')
		commands_list[i] = command

def test_config_using_telnet_vconsole(self):
	'''
	! This function is in testing and should not be considered reliable. !
	Use the telnet transfer script to initiate a telnet session and
	transfer config files.
	'''
	#TODO: This function is not going to be used and is for Linux containers.

	logging.info(f"Attempting to upload config files to container {self.hostname} using telnet")
	if self.hypervisor_telnet_port == 0:
		LOGGER.warning(f"Telnet port for {self.hostname} is not set.")
		if(input("Attempt to import from lab? (y/n): ") == "y"):
			if(os.path.exists("../python_config/src/handle_lab.py")):
				from handle_lab import test_import_vconsole_telnet
				LOGGER.debug("Handle lab script found, attemtping to import telnet ports.")
				test_import_vconsole_telnet(self.topology_a_part_of)
			else:
				LOGGER.warning("Handle lab script not found.")
				self.hypervisor_telnet_port = int(input("Enter telnet port for " + self.hostname + ": "))
		else:
			self.hypervisor_telnet_port = int(input("Enter telnet port for " + self.hostname + ": "))

	# Check if the file exists
	if os.path.exists(GLOBALS.telnet_transfer_path):
		module_name = os.path.splitext(os.path.basename(GLOBALS.telnet_transfer_path))[0]
		spec = importlib.util.spec_from_file_location(module_name, GLOBALS.telnet_transfer_path)
		if spec is None:
			LOGGER.error(f"Cannot create a module spec for {GLOBALS.telnet_transfer_path}")
			return None
		module = importlib.util.module_from_spec(spec)
		try:
			spec.loader.exec_module(module)
			LOGGER.debug(f"Successfully imported module '{module_name}' from '{GLOBALS.telnet_transfer_path}'")
		except Exception as e:
			LOGGER.error(f"Failed to import module '{module_name}' from '{GLOBALS.telnet_transfer_path}': {e}")
			return None
	else:
		logging.error("Telnet transfer script not found, cannot transfer container config using telnet")
		if (input("Validate globals? (y/n): ")== "y"):
			logging.info("Validating globals, try function again after validation")
			GLOBALS.validate_data()
		return
	if(self.hypervisor_telnet_port == 0):
		self.hypervisor_telnet_port = int(input("Enter telnet port for "+self.hostname+": "))

	if (len(self.config_copying_paths) != 0):
		for files in self.config_copying_paths:
			# Check if the file exists
			if os.path.exists(files['source']):
				LOGGER.debug(f"Found file {files['source']}")
				LOGGER.debug(f"Attempting to transfer file {files['source']} to {files['dest']}")
				module.telnet_transfer(GLOBALS.hypervisor_ipv4_address, self.hypervisor_telnet_port, files['source'], files['dest'],"","")
			else:
				logging.error(f"File {files['source']} not found")
	else:
		logging.info("No config present for"+self.hostname+". Skipping...")

def cisco_pki_config(node):
	'''Generate commmands to enroll a client device into a certificate authority.'''
	if node is None:
		LOGGER.error("Node is None")
		return
	if node.topology_a_part_of is None:
		LOGGER.error("Node topology_a_part_of is None")
		return
	else:
		topology = node.topology_a_part_of
	if (node.machine_data.device_type != 'cisco_ios' and node.machine_data.device_type != 'cisco_xe'):
		return
	##########################################

	# Is this node a CA?
	flag_setting_up_ca = False
	for ca in topology.certificate_authorities:
		for interfacei in range(node.get_interface_count()):
			interface = node.get_interface_no(interfacei)
			if id(interface) == id(ca):
				flag_setting_up_ca = True

	# TODO: Not all devices use 'flash'
	ca_database_path = 'flash:/ca'
	dns_name = f'{node.hostname}.{topology.domain_name_a}.{topology.domain_name_b}'
	subject_name = f'CN={node.hostname},O={topology.domain_name_a}.{topology.domain_name_b}'
	source_interface = f'{node.get_identity_interface().interface_type} {node.get_identity_interface().name}'
	# TODO: Mishandled secret
	password = 'sevenwsad'
	if flag_setting_up_ca:
		http_ca_enrollment_url = f'http://{node.hostname}.{topology.domain_name_a}.{topology.domain_name_b}'
		https_ca_enrollment_url = f'https://{node.hostname}.{topology.domain_name_a}.{topology.domain_name_b}'
		issuer_name = f'CN={node.hostname}-ca,O={topology.domain_name_a}.{topology.domain_name_b}'
		node.pki_config_commands.append(f'do mkdir {ca_database_path}')
		node.pki_config_commands.append('ip http server')
		node.pki_config_commands.append(f'ip http client source-interface {source_interface}')

		node.pki_config_commands.append(f'crypto pki server {node.hostname}_ca')
		node.pki_config_commands.append('hash sha256')
		node.pki_config_commands.append(f'database url {ca_database_path}/')
		node.pki_config_commands.append('database level complete')
		node.pki_config_commands.append(f'issuer-name {issuer_name}')
		node.pki_config_commands.append('grant auto')
		node.pki_config_commands.append('lifetime ca-certificate 7300')
		node.pki_config_commands.append('lifetime certificate 3650')
		node.pki_config_commands.append('no shut')

		node.pki_config_commands.append('no crypto pki trustpoint https_cert')
		node.pki_config_commands.append('crypto pki trustpoint https_cert')
		node.pki_config_commands.append(f'subject-name {subject_name}')
		node.pki_config_commands.append(f'subject-alt-name {dns_name}')
		node.pki_config_commands.append(f'enrollment url {http_ca_enrollment_url}')
		node.pki_config_commands.append('hash sha256')
		node.pki_config_commands.append('revocation-check none')

		node.pki_config_commands.append('ip http secure-server')
		node.pki_config_commands.append('crypto pki enroll https_cert')
		node.pki_config_commands.append('ip http secure-trustpoint https_cert')

		d = 'crypto pki export r1-ca pem terminal'
	else:
		# Setting up enrollment of pki client
		node.pki_config_commands.append(f'ip http client source-interface {source_interface}')
		
		for ca in topology.certificate_authorities:
			http_ca_enrollment_url = f'http://{ca.node_a_part_of.hostname}.{topology.domain_name_a}.{topology.domain_name_b}'
			https_ca_enrollment_url = f'https://{ca.node_a_part_of.hostname}.{topology.domain_name_a}.{topology.domain_name_b}'
			issuer_name = f'CN={ca.node_a_part_of.hostname}-ca,O={topology.domain_name_a}.{topology.domain_name_b}'
			ca_name = f'{ca.node_a_part_of.hostname}_ca'

			f'crypto pki trustpoint {ca_name}'
			'enrollment terminal'
			'revocation-check none'
			'exit'
			f'crypto pki authenticate {ca_name}'
			
			trustpoint_name = f'{node.hostname}_enroll_{ca_name}'
			node.pki_config_commands.append(f'crypto key generate rsa modulus 2048 label {trustpoint_name}')
			node.pki_config_commands.append(f'no crypto pki trustpoint {trustpoint_name}')
			node.pki_config_commands.append(f'crypto pki trustpoint {trustpoint_name}')
			if True:
				node.pki_config_commands.append(f'enrollment url {https_ca_enrollment_url}')
			else:
				node.pki_config_commands.append(f'enrollment url {http_ca_enrollment_url}')
			node.pki_config_commands.append(f'rsakeypair {trustpoint_name}')
			node.pki_config_commands.append(f'subject-name {subject_name}')
			node.pki_config_commands.append(f'subject-alt-name {dns_name}')
			node.pki_config_commands.append('revocation-check none')
			node.pki_config_commands.append('exit')
			node.pki_config_commands.append(f'crypto pki authenticate {trustpoint_name}')
			node.pki_config_commands.append(f'crypto pki enroll {trustpoint_name}')
	