from __future__ import annotations
from project_globals import GLOBALS
from netmiko import ConnectHandler, BaseConnection
import ipaddress
import logging
import os
from pathlib import Path
import importlib.util
from pydantic import BaseModel
from typing import Optional, List, Dict
LOGGER = logging.getLogger('my_logger')
class Node(BaseModel):
	def __repr__(self):
		return f"Node(name={self.hostname})"
	class Config:
		validate_assignment = True
		arbitrary_types_allowed = True
		from_attributes = True
		fields = {
			'interfaces': {'exclude': True},
			'main_dhcp_exclusion_end': {'exclude': True},
			'outreach_dhcp_exclusion_start': {'exclude': True},
			'outreach_dhcp_exclusion_end': {'exclude': True},
		}
	hostname: str
	domain_override: Optional[str]=None
	netmiko_connection: Optional["ConnectHandler"]=None
	machine_data: Optional[MachineData]=None
	topology_a_part_of: Optional[Topology]=None
	category_override: Optional[str]=None
	hypervisor_telnet_port: Optional[int]=0
	config_path: Optional[str]=None
	config_copying_paths: Optional[List[Dict[str, str]]]=[]  # List of dictionaries, each with "source" and "dest" as keys
	local_user: str
	local_password: str
	oob_interface: Optional[Interface]=None
	ipv4_default_gateway: Optional[ipaddress.IPv4Address]=None
	ipv6_default_gateway: Optional[ipaddress.IPv6Address]=None
	ipv4_dns: Optional[ipaddress.IPv4Address]=None
	ipv6_dns: Optional[ipaddress.IPv6Address]=None
	ipv4_ntp_server: Optional[ipaddress.IPv4Address]=None
	ipv6_ntp_server: Optional[ipaddress.IPv6Address]=None
	__interfaces: List[Interface]=[]
	# Configuration commands storage
	ssh_stub_config_commands: List[str] = []
	interface_config_commands: List[str] = []
	def add_interface(self, iface: Interface):
		self.__interfaces.append(iface)
		iface.node_a_part_of=self
	def get_interface(self, name: str):
		for iface in self.__interfaces:
			if iface.name == name:
				return iface
	def get_interface_no(self, index: int):
		if index < 0 or index >= len(self.__interfaces):
			raise IndexError("Interface index out of range.")
		return self.__interfaces[index]
	def get_interface_count(self):
		return len(self.__interfaces)
	def generate_interfaces_config(self):
		LOGGER.info(f"Generating interfaces config for {self.hostname}")
		if self.machine_data.device_type == "cisco_ios" or self.machine_data.device_type == "cisco_xe":
			self.interface_config_commands = []
			
			for index_a in range (self.get_interface_count()):
				interface = self.get_interface_no(index_a)
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
					self.interface_config_commands += [
					'interface r '+interface_group,
					'channel-group '+str(interface.interfaces[0].channel_group)+" mode active",
					'no shutdown'
					]
				self.interface_config_commands += ["interface " +interface.name]
				# Is it a subinterface?
				# If it contains a period, it's a subinterface
				if interface.name.find(".") > 0:
					# split the interface name on the period and get the 2nd part
					vlan = interface.name.split(".")[1]
					self.interface_config_commands += [f"encapsulation dot1Q {vlan}"]
				# Does it have an ip address?
				if interface.ipv4_address:
					# Is the machine multilayer?
					# It is not applicable to "vlan" interfaces but nevermind
					if self.machine_data.category == "multilayer" and (interface.name.find("vlan") == -1) and (interface.name.find("loop") == -1) and (interface.name != "l0"):
						self.interface_config_commands += ["no switchport"]
					temp_network=ipaddress.IPv4Network(f"0.0.0.0/{interface.ipv4_cidr}")
					self.interface_config_commands += [
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
							self.interface_config_commands += [
								"switchport trunk encapsulation dot1q",
								"switchport mode trunk",
								"switchport trunk native vlan 933",
								'switchport trunk allowed vlan '+allowed_vlans
							]
						else:
							self.interface_config_commands += [
								"switchport mode access",
								"switchport access vlan "+str(interface.vlans[0].number)
							]
						self.interface_config_commands += ["switchport nonegotiate"]
						self.interface_config_commands += ["no shutdown"]
						
			

			# Send the commands to file for review
			out_path = Path("../python_config/output/interfaces/")
			out_path.mkdir(exist_ok=True, parents=True)
			with open(os.path.join(out_path,self.hostname+'_interfaces.txt'), 'w') as f:
				for command in self.interface_config_commands:
					print(command, file=f)
		if self.machine_data.device_type == "debian":
			pass
	def apply_interfaces_config_netmiko(self):
		LOGGER.info(f"Applying interfaces config for {self.hostname}")
		if(self.machine_data.device_type == "debian" 
		or self.machine_data.device_type == "ubuntu" 
		or self.machine_data.device_type == "alpine"):
			device_type = "linux"
		else:
			device_type = self.machine_data.device_type
		# device data for Netmiko
		device = {
				'device_type': device_type, 
				'host': str(self.oob_interface.ipv4_address), 
				'username': self.local_user,
				'password': self.local_password,
				'secret': self.local_password, 
				'port': 22,
				'verbose': True,
				'conn_timeout': 30,
			}
		# Connect
		LOGGER.info(f"Connecting to {self.hostname} with device type {device_type}")
		try:
			connection = ConnectHandler(**device)
		except Exception as e:
			LOGGER.error(f"Error connecting to {self.hostname} with netmiko: {e}")
			return
		LOGGER.info(f"Successfully connected to {self.hostname} with netmiko")

		
		output = connection.send_config_set(self.interface_config_commands)
		
		# Send the commands to file for review
		out_path = Path("../python_config/output/logs/netmiko/")
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,self.hostname+'_interfaces.log'), 'w') as f:
			print(output, file=f)
		
		connection.disconnect()
		LOGGER.info(f"Successfully disconnected from {self.hostname}")
	def generate_ssh_stub(self):
		if(self.machine_data is None):
			LOGGER.warning(f"Node {self.hostname} has no machine data, skipping ssh stub config generation")
			return
		if(self.oob_interface is None):
			LOGGER.warning(f"Node {self.hostname} has no oob interface, skipping ssh stub config generation")
			return
		if(self.local_user is None):
			LOGGER.warning(f"Node {self.hostname} has no local username, skipping ssh stub config generation")
			return
		if(self.local_password is None):
			LOGGER.warning(f"Node {self.hostname} has no local password, skipping ssh stub config generation")
			return
		if(self.machine_data.device_type == 'cisco_ios' or self.machine_data.device_type == 'cisco_xe'):
			self.ssh_stub_config_commands = []
			print(f"Generating SSH stub config for {self.hostname}")
			#self.ssh_stub_config_commands.append(f'conf t')

			self.ssh_stub_config_commands.append(f"hostname {self.hostname}")
			self.ssh_stub_config_commands.append(f"username {self.local_user} privilege 15 secret {self.local_password}")
			self.ssh_stub_config_commands.append("service password-encryption")
			if(self.machine_data.device_type == 'cisco_xe'):
				if(self.domain_override is None):
					self.ssh_stub_config_commands.append(f"ip domain name {self.topology_a_part_of.domain_name_a}.{self.topology_a_part_of.domain_name_b}")
				else:
					self.ssh_stub_config_commands.append(f"ip domain name {self.domain_override}")
			else:
				if(self.domain_override is None):
					self.ssh_stub_config_commands.append(f"ip domain-name {self.topology_a_part_of.domain_name_a}.{self.topology_a_part_of.domain_name_b}")
				else:
					self.ssh_stub_config_commands.append(f"ip domain-name {self.domain_override}")
			self.ssh_stub_config_commands.append("crypto key generate rsa modulus 2048 label ssh")
			self.ssh_stub_config_commands.append("ip ssh version 2")
		
			self.ssh_stub_config_commands.append(f"interface {self.oob_interface.name}")
			# What if it is an etherchannel or subinterface?
			if(len(self.oob_interface.vlans) != 0):
				LOGGER.error(f"Vlans are not supported for oob interface {self.oob_interface.name} on {self.hostname}")
				return
			if(len(self.oob_interface.interfaces) != 0):
				LOGGER.error(f"Port-channel groups are currently unsupported for oob interface {self.oob_interface.name} on {self.hostname}")
				return
			if self.machine_data.category == "multilayer" and (self.oob_interface.name.find("vlan") == -1) and (self.oob_interface.name.find("loop") == -1) and (self.oob_interface.name != "l0"):
				self.ssh_stub_config_commands.append("no switchport")

			temp_network=ipaddress.IPv4Network(f"0.0.0.0/{self.oob_interface.ipv4_cidr}")
			self.ssh_stub_config_commands.append(f'ip address {self.oob_interface.ipv4_address} {temp_network.netmask}')
			self.ssh_stub_config_commands.append("no shutdown")
			self.ssh_stub_config_commands.append("exit")
		
			self.ssh_stub_config_commands.append("line vty 0 4")
			self.ssh_stub_config_commands.append("login local")
			self.ssh_stub_config_commands.append("transport input ssh")
			self.ssh_stub_config_commands.append("exec-timeout 0 0")

		elif(self.machine_data.device_type=="debian" or self.machine_data.device_type=="alpine"):
			self.ssh_stub_config_commands = []
			self.ssh_stub_config_commands.append(f'ip add add {self.oob_interface.ipv4_address}/{self.oob_interface.ipv4_cidr} dev {self.oob_interface.name}')
			self.ssh_stub_config_commands.append(f'ip link set dev {self.oob_interface.name} up')
		
		
		print(f"########## SSH Config for {self.hostname}:")
		for printable in self.ssh_stub_config_commands:
			print(printable)
		
		# Send the commands to file for review
		out_path = Path("../python_config/output/stubs/")
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(out_path,self.hostname+'_stub.txt'), 'w') as f:
			for command in self.ssh_stub_config_commands:
				print(command, file=f)
	def config_using_telnet_vconsole(self):
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
					module.telnet_transfer(GLOBALS.hypervisor_ssh_host, self.hypervisor_telnet_port, files['source'], files['dest'],"","")
				else:
					logging.error(f"File {files['source']} not found")
		else:
			logging.info("No config present for"+self.hostname+". Skipping...")