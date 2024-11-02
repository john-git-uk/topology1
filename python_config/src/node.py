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
from convert import cidr_to_wildmask, ipv4_netid, cidr_to_netmask
LOGGER = logging.getLogger('my_logger')
class Node(BaseModel):
	def __repr__(self):
		return f"Node(name={self.hostname})"
	class Config:
		debug = True # Enable debug mode
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
	__containers: List[Container]=[]
	# Configuration commands storage
	ssh_stub_config_commands: List[str] = []
	interface_config_commands: List[str] = []
	stp_vlan_config_commands: List[str] = []
	fhrp_config_commands: List[str] = []
	ospf_static_base_config_commands: List[str] = []
	dhcp_config_commands: List[str] = []
	wan_config_commands: List[str] = []
	ntp_config_commands: List[str] = []
	def add_interface(self, iface: Interface):
		if self.machine_data.device_type == "cisco_ios" or self.machine_data.device_type == "cisco_xe":
			if iface.interface_type == "mactap":
				LOGGER.critical(f"Cannot add mac tap interface to {self.hostname} due to not being compatible with Cisco IOS")
				exit(1)
			elif iface.interface_type == "bridge":
				LOGGER.critical(f"Cannot add bridge interface to {self.hostname} due to not being supported with Cisco IOS")
				exit(1)
		elif self.machine_data.device_type == "debian" or self.machine_data.device_type == "proxmox":
			if iface.interface_type == "port-channel":
				LOGGER.critical(f"Cannot add port-channel interface to {self.hostname} due to not being supported with Debian")
				exit(1)
			elif iface.interface_type == "vlan":
				LOGGER.critical(f"Cannot add vlan type interface to {self.hostname} due to not being supported with Debian")
				exit(1)
			elif iface.interface_type == "tunnel":
				LOGGER.critical(f"Cannot add tunnel interface to {self.hostname} due to not being supported with Debian")
				exit(1)
			elif iface.interface_type == "fast ethernet":
				iface.interface_type = "ethernet"
			elif iface.interface_type == "gigabit ethernet":
				iface.interface_type = "ethernet"
		else:
			LOGGER.critical(f"Cannot add interface to {self.hostname} due to unimplemented machine data type selection")
		self.__interfaces.append(iface)
		iface.node_a_part_of=self
	def get_interface(self, type: str, name: str):
		for iface in self.__interfaces:
			if iface.name == name:
				if iface.interface_type == type:
					return iface
		LOGGER.warning(f"Interface {name} of type {type} not found on {self.hostname}")
	def get_interface_no(self, index: int):
		if index < 0 or index >= len(self.__interfaces):
			raise IndexError("Interface index out of range.")
		return self.__interfaces[index]
	def get_interface_count(self):
		return len(self.__interfaces)
	def add_container(self, container: Container):
		self.__containers.append(container)
	def get_container(self, name: str):
		for container in self.__containers:
			if container.node_data.hostname == name:
				return container
	def get_container_count(self):
		return len(self.containers)
	def get_container_no(self, index: int):
		if index < 0 or index >= len(self.containers):
			raise IndexError("Container index out of range.")
		return self.containers[index]
	def generate_interfaces_config(self):
		LOGGER.info(f"Generating interfaces config for {self.hostname}")
		if self.machine_data.device_type == "cisco_ios" or self.machine_data.device_type == "cisco_xe":
			self.interface_config_commands = []
			access_segment = None
			for seg in self.topology_a_part_of.access_segments:
				for node in seg.nodes:
					if node.hostname == self.hostname:
						access_segment = seg
			
			for index_a in range (self.get_interface_count()):
				interface = self.get_interface_no(index_a)
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
					self.interface_config_commands += [
					'interface r '+interface_group,
					'channel-group '+str(interface.interfaces[0].channel_group)+" mode active",
					'no shutdown'
					]
				self.interface_config_commands += [f"interface {interface.interface_type} {interface.name}"]
				# Is it a subinterface?
				# If it contains a period, it's a subinterface
				if interface.name.find(".") > 0:
					if access_segment is None:
						LOGGER.error(f"Subinterface assigned node {self.hostname} has no access segment, skipping interface config generation")
						return
					# split the interface name on the period and get the 2nd part
					vlan = interface.name.split(".")[1]
					self.interface_config_commands += [f"encapsulation dot1Q {vlan}"]
				# Does it have an ip address?
				if interface.ipv4_address:
					# Is the machine multilayer?
					# It is not applicable to "vlan" interfaces
					if self.machine_data.category == "multilayer" and (interface.interface_type == "vlan") and (interface.interface_type == "loopback"):
						self.interface_config_commands += ["no switchport"]
					temp_network=ipaddress.IPv4Network(f"0.0.0.0/{interface.ipv4_cidr}")
					self.interface_config_commands += [
						'ip address '+str(interface.ipv4_address)+' '+str(temp_network.netmask),
						'no shutdown'
					]
				else:
					# Does it have vlans?
					if interface.vlans:
						if access_segment is None:
							LOGGER.error(f"VLAN assigned node {self.hostname} has no access segment, skipping interface config generation")
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
			out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "interfaces"
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
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "logs" / "netmiko"
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
		
			self.ssh_stub_config_commands.append(f"interface {self.oob_interface.interface_type} {self.oob_interface.name}")
			# What if it is an etherchannel or subinterface?
			if(len(self.oob_interface.vlans) != 0):
				LOGGER.error(f"Vlans are not supported for oob interface {self.oob_interface.interface_type} {self.oob_interface.name} on {self.hostname}")
				return
			if(len(self.oob_interface.interfaces) != 0):
				LOGGER.error(f"Port-channel groups are currently unsupported for oob interface {self.oob_interface.interface_type} {self.oob_interface.name} on {self.hostname}")
				return
			if self.machine_data.category == "multilayer" and (self.oob_interface.interface_type == "vlan") and (self.oob_interface.interface_type == "loop"):
				self.ssh_stub_config_commands.append("no switchport")

			temp_network=ipaddress.IPv4Network(f"0.0.0.0/{self.oob_interface.ipv4_cidr}")
			self.ssh_stub_config_commands.append(f'ip address {self.oob_interface.ipv4_address} {temp_network.netmask}')
			self.ssh_stub_config_commands.append("no shutdown")
			self.ssh_stub_config_commands.append("exit")
		
			self.ssh_stub_config_commands.append("line vty 0 4")
			self.ssh_stub_config_commands.append("login local")
			self.ssh_stub_config_commands.append("transport input ssh")
			self.ssh_stub_config_commands.append("exec-timeout 0 0")
			self.ssh_stub_config_commands.append("line console 0")
			self.ssh_stub_config_commands.append("exec-timeout 0 0")
			self.ssh_stub_config_commands.append("exit")

		elif(self.machine_data.device_type=="debian" or self.machine_data.device_type=="alpine"):
			self.ssh_stub_config_commands = []
			self.ssh_stub_config_commands.append(f'ip add add {self.oob_interface.ipv4_address}/{self.oob_interface.ipv4_cidr} dev {self.oob_interface.name}')
			self.ssh_stub_config_commands.append(f'ip link set dev {self.oob_interface.name} up')
		
		
		#print(f"########## SSH Config for {self.hostname}:")
		#for printable in self.ssh_stub_config_commands:
		#	print(printable)
		
		# Send the commands to file for review
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "stubs"
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
	def generate_stp_vlan_config(self):
		if(self.machine_data.device_type == "cisco_ios" or self.machine_data.device_type == "cisco_xe"):
			if(self.machine_data.category == "multilayer" or self.machine_data.category == "switch"):
				LOGGER.info(f"Generating stp vlan config for {self.hostname}")
				access_segment = None
				for seg in self.topology_a_part_of.access_segments:
					for node in seg.nodes:
						if node.hostname == self.hostname:
							access_segment = seg
				if(access_segment is None):
					LOGGER.error(f"No access segment found for VLAN assigned node {self.hostname}, skipping stp vlan config generation")
					return
				self.stp_vlan_config_commands = []
				self.stp_vlan_config_commands += ['spanning-tree mode rapid-pvst']
				for vlan in access_segment.vlans:
					if(vlan.name == "default"):
						continue
					self.stp_vlan_config_commands += [
						'vlan '+str(vlan.number),
						'name '+vlan.name,
						'exit'
					]
					if vlan.fhrp0_priority is None:
						continue
					if(vlan.fhrp0_priority.node_a_part_of.hostname == self.hostname):
						self.stp_vlan_config_commands += [
							'spanning-tree vlan '+str(vlan.number)+' priority '+str(4096),
							'spanning-tree vlan '+str(vlan.number)+' root primary'
						]
					else:
						self.stp_vlan_config_commands += [
							'spanning-tree vlan '+str(vlan.number)+' priority '+str(0),
							'spanning-tree vlan '+str(vlan.number)+' root secondary'
						]
				# Send the commands to file for review
				out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "stp_vlan"
				out_path.mkdir(exist_ok=True, parents=True)
				with open(os.path.join(out_path,self.hostname+'_stp_vlan.txt'), 'w') as f:
					for command in self.stp_vlan_config_commands:
						print(command, file=f)
	def generate_fhrp_config(self):
		if(self.machine_data.device_type == "cisco_ios" or self.machine_data.device_type == "cisco_xe"):
			if(self.machine_data.category == "multilayer"):
				LOGGER.info(f"Generating fhrp config for {self.hostname}")
				access_segment = None
				for seg in self.topology_a_part_of.access_segments:
					for node in seg.fhrp:
						if node.hostname == self.hostname:
							access_segment = seg
				if(access_segment is None):
					LOGGER.debug(f"{self.hostname} not part of FHRP system.")
					return
				# For each node interfaces
				for interface in self.__interfaces:
					LOGGER.debug(f"Generating fhrp config for {self.hostname} working on interface {interface.interface_type} {interface.name}")
					# That is a SVI
					if(interface.interface_type == "vlan"):
						# Get the vlan from interface name
						vlan = access_segment.get_vlan_nom(int(interface.name))
						if(vlan == None):
							LOGGER.error(f"vlan {interface.name} not found for {self.hostname}")
							return
						self.fhrp_config_commands += [
							f'interface {interface.interface_type} {interface.name}',
							'standby 0 ip '+str(vlan.fhrp0_ipv4_address),
							'standby 0 preempt delay rel 60',
							'standby 0 timers msec 200 msec 650',
						]
						# If this node interface is the priority
						if(vlan.fhrp0_priority.node_a_part_of.hostname == self.hostname):
							self.fhrp_config_commands += ['standby 0 priority 200']
						else:
							self.fhrp_config_commands += ['standby 0 priority 111']
						# Send the commands to file for review
						out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "fhrp"
						out_path.mkdir(exist_ok=True, parents=True)
						with open(os.path.join(out_path,self.hostname+'_fhrp.txt'), 'w') as f:
							for command in self.fhrp_config_commands:
								print(command, file=f)
	def generate_ospf_static_base_config(self):
		if(self.machine_data.device_type == "cisco_ios" or self.machine_data.device_type == "cisco_xe"):
			if(self.machine_data.category == "multilayer" or self.machine_data.category == "router"):
				LOGGER.info(f"Generating ospf static base config for {self.hostname}")
				access_segment = None
				for seg in self.topology_a_part_of.access_segments:
					for node in seg.nodes:
						if node.hostname == self.hostname:
							access_segment = seg
				#if(access_segment is None):
				#	LOGGER.error(f"No access segment found for OSPF assigned node {self.hostname}, skipping ospf static base config generation")
				#	return
				if(self.hostname == "ISP"):
					LOGGER.error(f"ISP node is not currently supported for OSPF or static routing config generation, manual config required")
					return
				self.ospf_static_base_config_commands = []
				# If it connects to ISP it is a WAN port (TODO: Make this rely on a better data entry)
				if(self.get_wan_interface() is not None):
					self.ospf_static_base_config_commands += [
						f'ip route 0.0.0.0 0.0.0.0 {str(self.get_wan_interface().neighbour.ipv4_address)}'
					]
				
				ospf_commands=[]
				if(self.machine_data.category == "multilayer"):
					ospf_commands += ['ip routing']
				ospf_commands += ['router ospf 1']
				ospf_commands += ['auto-cost reference-bandwidth 100000']
				if(self.get_wan_interface() is not None):
					ospf_commands += ["default-information originate"]
				for interface in self.__interfaces:
					if(interface.ospf_participant):
						if(interface.ipv4_address is None):
							LOGGER.critical(f"Interface {interface.name} has no ip address, skipping ospf static base config generation")
							return
						if (not interface.name.startswith("vlan"))and(not interface.name.startswith("loop")):
							if(interface.neighbour is None):
								LOGGER.critical(f"Interface {interface.name} has no neighbour, skipping ospf static base config generation")
								return
							#if(interface.neighbour.ipv4_address is None):
							#	LOGGER.critical(f"Interface {interface.name} has neighbour without ip address, skipping ospf static base config generation")
							#	return
						# If this interface has an ip address
						# Advertise the network
						ospf_commands += [f'network {str(ipv4_netid(interface.ipv4_address,interface.ipv4_cidr))} {str(cidr_to_wildmask(interface.ipv4_cidr))} area 0']
					# If layer 3 check passive
					if(interface.ospf_passive and interface.ipv4_address is not None):
						ospf_commands += [f'passive-interface {interface.name}']
				
				ospf = False
				for command in ospf_commands:
					if command.startswith("network"):
						ospf = True
				if ospf == False:
					ospf_commands = []
					LOGGER.debug("no interfaces participating in ospf, no config required")
				self.ospf_static_base_config_commands += ospf_commands

				# Send the commands to file for review
				out_path = Path("../python_config/output/routing_base/")
				out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "routing_base"
				out_path.mkdir(exist_ok=True, parents=True)
				with open(os.path.join(out_path,self.hostname+'_routing_base.txt'), 'w') as f:
					for command in self.ospf_static_base_config_commands:
						print(command, file=f)
	def generate_dhcp_config(self):
		# TODO: Make this part of data not hardcoded
		###############################################
		dhcp_server=None
		if(self.hostname == "SW3"):
			dhcp_server="SW3"
		if(self.hostname == "R3"):
			dhcp_server="R3"
		dhcp_helper=None
		if(self.hostname == "SW4"):
			dhcp_helper=self.topology_a_part_of.get_node("R1").get_interface("loopback","0")
		###############################################
		if(self.machine_data.device_type == "cisco_ios" or self.machine_data.device_type == "cisco_xe"):
			if(self.machine_data.category == "multilayer" or self.machine_data.category == "router"):
				LOGGER.info(f"Generating dhcp config for {self.hostname}")
				access_segment = None
				for seg in self.topology_a_part_of.access_segments:
					for node in seg.nodes:
						if node.hostname == self.hostname:
							access_segment = seg
				if(self.hostname == dhcp_server):
					for vlan in access_segment.vlans:
						if (vlan.dhcp_exclusion_start is not None) and (vlan.dhcp_exclusion_end is not None):
							if len(vlan.dhcp_exclusion_start) == 0:
								continue
							LOGGER.debug(f"Generating dhcp config for {self.hostname} working on vlan {vlan.name}")

							if(len(vlan.dhcp_exclusion_start) != len(vlan.dhcp_exclusion_end)):
								LOGGER.critical(f"DHCP exclusion start and end do not match for vlan {vlan.name}")
								return

							for exclusion in range(len(vlan.dhcp_exclusion_start)):
								self.dhcp_config_commands += [f'ip dhcp excluded-address {str(vlan.dhcp_exclusion_start[exclusion])} {str(vlan.dhcp_exclusion_end[exclusion])}']
							if(vlan.fhrp0_ipv4_address is not None):
								gateway = vlan.fhrp0_ipv4_address
							else:
								if(vlan.default_gateway is None):
									LOGGER.critical(f"default gateway not set for vlan {vlan.name}")
									continue
								gateway = vlan.default_gateway.ipv4_address
							self.dhcp_config_commands += [
								'ip dhcp pool '+str(vlan.number),
								'network '+str(vlan.ipv4_netid)+' /'+str(vlan.ipv4_cidr),
								'default-router '+str(gateway),
								'domain-name '+self.topology_a_part_of.domain_name_a+'.'+self.topology_a_part_of.domain_name_b,
								# TODO: Add dns servers
								'dns-server '+str(self.topology_a_part_of.dns_private[0].ipv4_address),
								'exit'
							]
				if(dhcp_helper is not None):
					for interface in self.__interfaces:
						if(interface.ipv4_address is None):
							continue
						self.dhcp_config_commands += [f"interface {interface.interface_type} {interface.name}"]
						self.dhcp_config_commands += [f"ip dhcp helper address {dhcp_helper.ipv4_address}"]
				
				# Send the commands to file for review
				out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "dhcp"
				out_path.mkdir(exist_ok=True, parents=True)
				with open(os.path.join(out_path,self.hostname+'_dhcp.txt'), 'w') as f:
					for command in self.dhcp_config_commands:
						print(command, file=f)
	def generate_wan_config(self):
		# TODO: Make this part of data not hardcoded
		###############################################
		###############################################
		if(self.machine_data.device_type == "cisco_ios" or self.machine_data.device_type == "cisco_xe"):
			if(self.machine_data.category == "router"):
				LOGGER.info(f"Generating wan config for {self.hostname}")
				
				# Find the interface that connects to ISP
				
				if(self.get_wan_interface() is None):
					LOGGER.debug(f"{self.hostname} has no wan interface, skipping wan config generation")
					return
				self.wan_config_commands = []
				self.wan_config_commands += [
					f'ip access-list extended NAT',
					f'10 permit ip 10.133.0.0 {cidr_to_wildmask(16)} {ipv4_netid(self.topology_a_part_of.exit_interface_main.ipv4_address,24)} {cidr_to_wildmask(24)}',
					f'20 deny ip 10.133.0.0 {cidr_to_wildmask(16)} 10.133.0.0 {cidr_to_wildmask(16)}',
					f'30 permit ip 10.133.0.0 {cidr_to_wildmask(16)} any',
					f'10000 deny ip any any',
					"exit",
					f'ip nat inside source list NAT interface {self.get_wan_interface().interface_type} {self.get_wan_interface().name} overload'
				]
				
				for interface in self.__interfaces:
					if(interface.ipv4_address is None):
						continue
					if(interface.interface_type == "loop"):
						continue
					if(interface.interface_type == "tunnel"):
						continue
					if(interface == self.get_wan_interface()):
						self.wan_config_commands += [
							f'interface {interface.interface_type} {interface.name}',
							f'ip nat outside',
							f'exit',
						]
					else:
						self.wan_config_commands += [
							f'interface {interface.interface_type} {interface.name}',
							f'ip nat inside',
							f'exit',
						]
				
				self.wan_config_commands += [
					"crypto isakmp policy 10",
					"en aes 256",
					"auth pre-share",
					"group 14",
					"lifetime 3600",
					"exit",
				]
				# TODO: Make this part of data not hardcoded
				if self.hostname == "R1":
					self.wan_config_commands += [
						f"crypto isakmp key vpnsecretkey13 address {self.topology_a_part_of.get_node("R3").get_wan_interface().ipv4_address}",
					]
				if self.hostname == "R2":
					self.wan_config_commands += [
						f"crypto isakmp key vpnsecretkey23 address {self.topology_a_part_of.get_node("R3").get_wan_interface().ipv4_address}",
					]
				if self.hostname == "R3":
					self.wan_config_commands += [
						f"crypto isakmp key vpnsecretkey13 address {self.topology_a_part_of.get_node("R1").get_wan_interface().ipv4_address}",
						f"crypto isakmp key vpnsecretkey23 address {self.topology_a_part_of.get_node("R2").get_wan_interface().ipv4_address}",
					]

				self.wan_config_commands += [
					"crypto ipsec transform-set ESP-AES256-SHA esp-aes 256 esp-sha-hmac",
					"mode tunnel",
					"exit",
				]

				self.wan_config_commands += [
					"ip access-list extended vpn_traff",
					f"deny ip any 192.168.2.0 {cidr_to_wildmask(24)}",
					f"permit ip 10.133.0.0 {cidr_to_wildmask(16)} 10.133.0.0 {cidr_to_wildmask(16)}",
					"exit",
					"crypto ipsec profile VPNPROFILE",
					"set transform-set ESP-AES256-SHA",
				]

				for tunnel in self.__interfaces:
					if tunnel.interface_type == "tunnel":
						# Find ospf neighbour and validate data
						ospf_neighbour=None
						if(tunnel.ipv4_address is None):
							LOGGER.critical(f"{self.hostname} - {tunnel.name} has no ipv4 address, cannot configure VPN, skipping node config...")
							return
						if(tunnel.ipv4_cidr is None):
							LOGGER.critical(f"{self.hostname} - {tunnel.name} has no ipv4 cidr, cannot configure VPN, skipping node config...")
							return
						if(tunnel.tunnel_destination is None):
							LOGGER.critical(f"{self.hostname} - {tunnel.name} has no tunnel destination, cannot configure VPN, skipping node config...")
							return
						for neigh in tunnel.tunnel_destination.node_a_part_of.__interfaces:
							if(neigh.interface_type == "loopback" and neigh.name == "0"):
								if(neigh.ipv4_address is None):
									LOGGER.critical(f"{neigh.interface_type} {neigh.name} has no ipv4 address, cannot configure VPN, skipping node config...")
									return
								if(neigh.ipv4_cidr is None):
									LOGGER.critical(f"{neigh.interface_type} {neigh.name} has no ipv4 cidr, cannot configure VPN, skipping node config...")
									return
								ospf_neighbour=neigh.ipv4_address

						self.wan_config_commands += [
							f"interface {tunnel.interface_type} {tunnel.name}",
							f"ip address {tunnel.ipv4_address} {cidr_to_netmask(tunnel.ipv4_cidr)}",
							f"tunnel source {self.get_wan_interface().ipv4_address}",
							"tunnel mode ipsec ipv4",
							f"tunnel destination {tunnel.tunnel_destination.ipv4_address}",
							"tunnel protection ipsec profile VPNPROFILE",
							"ip ospf network point-to-point",
							"no shutdown",
							"exit",
							# Add static routes to prevent advertisments of VPN taking precidense
							f"ip route {tunnel.tunnel_destination.ipv4_address} 255.255.255.255 {self.get_wan_interface().neighbour.ipv4_address}",
							"router ospf 1",
							f"neighbor {ospf_neighbour}",
							"exit",
						]

						# Send the commands to file for review
						t_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "wan"
						t_path.mkdir(exist_ok=True, parents=True)
						with open(os.path.join(t_path,self.hostname+'_wan.txt'), 'w') as f:
							for command in self.wan_config_commands:
									print(command, file=f)
	def generate_ntp_config(self):
		if(self.machine_data.device_type == "cisco_ios" or self.machine_data.device_type == "cisco_xe"):
			LOGGER.info(f"Generating ntp config for {self.hostname}")

			self.ntp_config_commands += [
				"clock timezone GMT 0",
				"clock summer-time BST recurring last Sun Mar 1:00 last Sun Oct 2:00",
				"ntp authenticate",
				f"ntp authentication-key 1 md5 {self.topology_a_part_of.ntp_password}",
				"ntp trusted-key 1",
				f"ntp server {self.topology_a_part_of.ntp_public}",
			]
			# Check if the master
			master = False
			for interface in self.__interfaces:
				if (id(interface) == id(self.topology_a_part_of.ntp_master)):
					self.ntp_config_commands += [
						f'ntp master',
					]
					master = True
					break
			if not master:

				if(self.topology_a_part_of.ntp_master is not None):

					self.ntp_config_commands += [
						f'ntp server {self.topology_a_part_of.ntp_master.ipv4_address} key 1 prefer',
					]
		
			self.ntp_config_commands += [	
				"ntp update-calendar"
			]
			# TODO: Hardcoded
			found_interface = False
			for interface in self.__interfaces:
				if (interface.name == "30") and (interface.interface_type == "vlan"):
					self.ntp_config_commands += [
					f'ntp source {interface.interface_type} {interface.name}'
					]
					found_interface = True
					break
				
				if (interface.name=="0") and (interface.interface_type == "loopback"):
					self.ntp_config_commands += [
					f'ntp source {interface.interface_type} {interface.name}'
					]
					found_interface = True
					break
			if not found_interface:
				LOGGER.error (f"Could not find interface for ntp source for {self.hostname}")

			# Send the commands to file for review
			t_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "ntp"
			t_path.mkdir(exist_ok=True, parents=True)
			with open(os.path.join(t_path,self.hostname+'_ntp.txt'), 'w') as f:
				for command in self.ntp_config_commands:
						print(command, file=f)
			
	def get_wan_interface(self):
		# TODO: Make this data not rely on ISP node and rely on topology exits or site exits or something
		# TODO: This assumes there is only one wan interface on a node
		# TODO: Was channel group zero actually undefined or was it used by cisco?
		LOGGER.debug(f"Finding wan interface for {self.hostname}")
		for interface in self.__interfaces:
			if(interface.ipv4_address is None):
				continue
			if(interface.interface_type == "loopback"):
				continue
			if(interface.interface_type == "vlan"):
				continue
			if(interface.channel_group is not None):
				continue
			if(interface.neighbour.node_a_part_of.hostname == "ISP"):
				return interface
		return None