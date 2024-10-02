from project_globals import get_globals, Globals
from topology_data import *
import logging
import pexpect
import sys
import psutil
import re
import json,time,urllib
from tabulate import tabulate
import os
from pathlib import Path
import configparser
from scp import SCPClient
from dotenv import load_dotenv
import requests
import importlib.util
import libvirt
LOGGER = logging.getLogger('my_logger')
def generate_interfaces_config(node: "Node"):
	LOGGER.info(f"Generating interfaces config for {node.hostname}")
	if node.machine_data.device_type == "cisco_ios" or node.machine_data.device_type == "cisco_xe":
		node.interface_config_commands = []
		
		for index_a in range (node.get_interface_count()):
			interface = node.get_interface_no(index_a)
			LOGGER.info(f"Configuring interface {interface.name}")
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
					interface_group += member.name
				node.interface_config_commands += [
				'interface r '+interface_group,
				'channel-group '+str(interface.interfaces[0].channel_group)+" mode active",
				'no shutdown'
				]
			node.interface_config_commands += ["interface " +interface.name]
			# Is it a subinterface?
			# If it contains a period, it's a subinterface
			if interface.name.find(".") > 0:
				# split the interface name on the period and get the 2nd part
				vlan = interface.name.split(".")[1]
				node.interface_config_commands += [f"encapsulation dot1Q {vlan}"]
			# Does it have an ip address?
			if interface.ipv4_address:
				# Is the machine multilayer?
				# It is not applicable to "vlan" interfaces but nevermind
				if node.machine_data.category == "multilayer" and (interface.name.find("vlan") == -1) and (interface.name.find("loop") == -1) and (interface.name != "l0"):
					node.interface_config_commands += [f"no switchport"]
				temp_network=ipaddress.IPv4Network(f"0.0.0.0/{interface.ipv4_cidr}")
				node.interface_config_commands += [
					'ip address '+str(interface.ipv4_address)+' '+str(temp_network.netmask),
					'no shutdown'
				]
			else:
				# Does it have vlans?
				if interface.vlans:
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
					
		

		# Send the commands to file for review
		out_path = Path("../python_config/output/interfaces/")
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,node.hostname+'_interfaces.txt'), 'w') as f:
			for command in node.interface_config_commands:
				print(command, file=f)
	if node.machine_data.device_type == "debian":
		pass
def apply_interfaces_config_netmiko(node: "Node"):
	LOGGER.info(f"Applying interfaces config for {node.hostname}")
	if(node.machine_data.device_type == "debian" 
	or node.machine_data.device_type == "ubuntu" 
	or node.machine_data.device_type == "alpine"):
		device_type = "linux"
	else:
		device_type = node.machine_data.device_type
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
	out_path = Path("../python_config/output/logs/netmiko/")
	out_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(out_path,node.hostname+'_interfaces.log'), 'w') as f:
		print(output, file=f)
	
	connection.disconnect()
	LOGGER.info(f"Successfully disconnected from {node.hostname}")
def generate_ssh_stub(node: "Node"):
	if(node.machine_data == None):
		LOGGER.warning(f"Node {node.hostname} has no machine data, skipping ssh stub config generation")
		return
	if(node.oob_interface == None):
		LOGGER.warning(f"Node {node.hostname} has no oob interface, skipping ssh stub config generation")
		return
	if(node.local_user == None):
		LOGGER.warning(f"Node {node.hostname} has no local username, skipping ssh stub config generation")
		return
	if(node.local_password == None):
		LOGGER.warning(f"Node {node.hostname} has no local password, skipping ssh stub config generation")
		return
	if(node.machine_data.device_type == 'cisco_ios' or node.machine_data.device_type == 'cisco_xe'):
		node.ssh_stub_config_commands = []
		print(f"Generating SSH stub config for {node.hostname}")
		#node.ssh_stub_config_commands.append(f'conf t')

		node.ssh_stub_config_commands.append(f"hostname {node.hostname}")
		node.ssh_stub_config_commands.append(f"username {node.local_user} privilege 15 secret {node.local_password}")
		node.ssh_stub_config_commands.append(f"service password-encryption")
		if(node.machine_data.device_type == 'cisco_xe'):
			if(node.domain_override == None):
				node.ssh_stub_config_commands.append(f"ip domain name {node.topology_a_part_of.domain_name_a}.{node.topology_a_part_of.domain_name_b}")
			else:
				node.ssh_stub_config_commands.append(f"ip domain name {node.domain_override}")
		else:
			if(node.domain_override == None):
				node.ssh_stub_config_commands.append(f"ip domain-name {node.topology_a_part_of.domain_name_a}.{node.topology_a_part_of.domain_name_b}")
			else:
				node.ssh_stub_config_commands.append(f"ip domain-name {node.domain_override}")
		node.ssh_stub_config_commands.append(f"crypto key generate rsa modulus 2048 label ssh")
		node.ssh_stub_config_commands.append(f"ip ssh version 2")
	
		node.ssh_stub_config_commands.append(f"interface {node.oob_interface.name}")
		# What if it is an etherchannel or subinterface?
		if(len(node.oob_interface.vlans) != 0):
			LOGGER.error(f"Vlans are not supported for oob interface {node.oob_interface.name} on {node.hostname}")
			return
		if(len(node.oob_interface.interfaces) != 0):
			LOOGER.error(f"Port-channel groups are currently unsupported for oob interface {node.oob_interface.name} on {node.hostname}")
			return
		if node.machine_data.category == "multilayer" and (node.oob_interface.name.find("vlan") == -1) and (node.oob_interface.name.find("loop") == -1) and (node.oob_interface.name != "l0"):
			node.ssh_stub_config_commands.append(f"no switchport")

		temp_network=ipaddress.IPv4Network(f"0.0.0.0/{node.oob_interface.ipv4_cidr}")
		node.ssh_stub_config_commands.append(f'ip address {node.oob_interface.ipv4_address} {temp_network.netmask}')
		node.ssh_stub_config_commands.append(f"no shutdown")
		node.ssh_stub_config_commands.append(f"exit")
	
		node.ssh_stub_config_commands.append(f"line vty 0 4")
		node.ssh_stub_config_commands.append(f"login local")
		node.ssh_stub_config_commands.append(f"transport input ssh")
		node.ssh_stub_config_commands.append(f"exec-timeout 0 0")

	elif(node.machine_data.device_type=="debian" or node.machine_data.device_type=="alpine"):
		node.ssh_stub_config_commands = []
		node.ssh_stub_config_commands.append(f'ip add add {node.oob_interface.ipv4_address}/{node.oob_interface.ipv4_cidr} dev {node.oob_interface.name}')
		node.ssh_stub_config_commands.append(f'ip link set dev {node.oob_interface.name} up')
	
	
	print(f"########## SSH Config for {node.hostname}:")
	for printable in node.ssh_stub_config_commands:
		print(printable)
	
	# Send the commands to file for review
	out_path = Path("../python_config/output/stubs/")
	out_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(out_path,node.hostname+'_stub.txt'), 'w') as f:
		for command in node.ssh_stub_config_commands:
			print(command, file=f)
def config_using_telnet_vconsole(node: "Node"):
	logging.info(f"Attempting to upload config files to container {node.hostname} using telnet")
	if node.hypervisor_telnet_port == 0:
		LOGGER.warning(f"Telnet port for {node.hostname} is not set.")
		if(input("Attempt to import from lab? (y/n): ") == "y"):
			if(os.path.exists("../python_config/src/handle_lab.py")):
				from handle_lab import test_import_vconsole_telnet
				LOGGER.debug("Handle lab script found, attemtping to import telnet ports.")
				test_import_vconsole_telnet(node.topology_a_part_of)
			else:
				LOGGER.warning("Handle lab script not found.")
				node.hypervisor_telnet_port = int(input("Enter telnet port for " + node.hostname + ": "))
		else:
			node.hypervisor_telnet_port = int(input("Enter telnet port for " + node.hostname + ": "))

	# Check if the file exists
	if os.path.exists(GLOBALS.telnet_transfer_path):
		module_name = os.path.splitext(os.path.basename(get_globals().telnet_transfer_path))[0]
		spec = importlib.util.spec_from_file_location(module_name, get_globals().telnet_transfer_path)
		if spec is None:
			LOGGER.error(f"Cannot create a module spec for {get_globals().telnet_transfer_path}")
			return None
		module = importlib.util.module_from_spec(spec)
		try:
			spec.loader.exec_module(module)
			LOGGER.debug(f"Successfully imported module '{module_name}' from '{get_globals().telnet_transfer_path}'")
		except Exception as e:
			LOGGER.error(f"Failed to import module '{module_name}' from '{get_globals().telnet_transfer_path}': {e}")
			return None
	else:
		logging.error("Telnet transfer script not found, cannot transfer container config using telnet")
		if (input("Validate globals? (y/n): ")== "y"):
			logging.info("Validating globals, try function again after validation")
			get_globals().validate_data()
		return
	if(node.hypervisor_telnet_port == 0):
		node.hypervisor_telnet_port = int(input("Enter telnet port for "+node.hostname+": "))

	if (len(node.config_copying_paths) != 0):
		for files in node.config_copying_paths:
			# Check if the file exists
			if os.path.exists(files['source']):
				LOGGER.debug(f"Found file {files['source']}")
				LOGGER.debug(f"Attempting to transfer file {files['source']} to {files['dest']}")
				module.telnet_transfer(get_globals().hypervisor_ssh_host, node.hypervisor_telnet_port, files['source'], files['dest'],"","")
			else:
				logging.error(f"File {files['source']} not found")
	else:
		logging.info("No config present for"+node.hostname+". Skipping...")