from __future__ import annotations
from project_globals import GLOBALS
from netmiko import ConnectHandler, BaseConnection
import paramiko
import ipaddress
import logging
import re
import os
from pathlib import Path
import importlib.util
from pydantic import BaseModel
from typing import Optional, List, Dict, Callable
from convert import cidr_to_wildmask, ipv4_netid, cidr_to_netmask
import copy
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
	paramiko_connection: Optional["paramiko.SSHClient"]=None
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
	radius_client_commands: List[str] = []
	pki_config_commands: List[str] = []
	additional_config_commands: List[str] = []
	additional_config: Callable[[Node], None] = None
	identity_interface: Optional[Interface]=None
	access_segment: Optional[AccessSegment]=None
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
			elif iface.interface_type == "fastethernet":
				iface.interface_type = "ethernet"
			elif iface.interface_type == "gigabitethernet":
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
		LOGGER.warning(f"Container {name} not found on {self.hostname}")

	def get_container_count(self):
		return len(self.__containers)

	def get_container_no(self, index: int):
		if index < 0 or index >= len(self.__containers):
			raise IndexError("Container index out of range.")
		return self.__containers[index]

	def get_access_segment(self):
		if self.access_segment is None:
			for seg in self.topology_a_part_of.access_segments:
				for node in seg.nodes:
					if node.hostname == self.hostname:
						access_segment = seg
						return access_segment
			LOGGER.warning(f"Access segment was requested but not found for {self.hostname}")
		else:
			return self.access_segment

	def get_identity_interface(self):
		if self.identity_interface != None:
			return self.identity_interface
		
		# TODO: Linux could be improved but possibly only by non-standardised naming conventions
		if self.machine_data.device_type == 'debian' \
			or self.machine_data.device_type == 'proxmox' \
			or self.machine_data.device_type == 'alpine':
			self.identity_interface = self.__interfaces[0]
			return self.__interfaces[0]

		# The rest is just for Cisco devices
		if self.machine_data.device_type != 'cisco_ios' and self.machine_data.device_type != 'cisco_xe':
			LOGGER.error(f"Identity interface was requested for {self.hostname}"
			+f" however device type is {self.machine_data.device_type} and only Debian or Alpine or Cisco devices are implemented")

		LOGGER.debug(f"Finding identity interface for {self.hostname}")
		# Build list of loopbacks in any order
		lowest = 65535
		lowest_index = 65536
		for count, interface in enumerate(self.__interfaces):
			if(interface.interface_type != "loopback"):
				continue
			if int(interface.name) < lowest:
				lowest = int(interface.name)
				lowest_index = count
		if lowest_index != 65536:
			self.identity_interface = self.__interfaces[lowest_index]
			return self.__interfaces[lowest_index]
		if self.get_access_segment() != None:
			# Check for manaagement vlan
			svis = []
			count = 0
			management_vlan = 0
			for vlanc in self.get_access_segment().vlans:
				if vlanc.name == "management":
					LOGGER.debug(f"Found management vlan: {vlanc.number}")
			# If we have a management vlan, check for a management interface
			if management_vlan != 0:
				for interface in self.__interfaces:
					if(interface.interface_type != "vlan"):
						continue
					if int(interface.name) == management_vlan:
						LOGGER.debug(f"Found management vlan for {self.hostname} named {interface.interface_type} {interface.name}")
						self.identity_interface = interface
						return interface
			else:
				LOGGER.debug(f"No management vlan found")

		LOGGER.warning(f"Struggling to find identity interface for {self.hostname}. Proceeding to set to interface with lowest IPv4.")
		
		# TODO: This should probably be checking if interface is up up, or just screem at the user
		lowest = ipaddress.ip_address("255.255.255.255")
		lowest_index = 65536
		for count, interface in enumerate(self.__interfaces):
			if(interface.ipv4_address is None):
				continue
			if(id(interface) == id(self.oob_interface)):
				continue
			if interface.ipv4_address < lowest:
				lowest = interface.ipv4_address
				lowest_index = count
		if lowest_index != 65536:
			self.identity_interface = self.__interfaces[lowest_index]
			return self.__interfaces[lowest_index]
		if self.identity_interface is None:
			if self.oob_interface is not None:
				LOGGER.error(f"The only vaild ipv4 interface for {self.hostname} was the oob interface after one was requested for id")
				self.identity_interface = self.oob_interface
				return self.oob_interface
			else:
				LOGGER.error(f"Could not find an ipv4 interface for {self.hostname} after one was requested for id")

	def get_wan_interface(self):
		# TODO: This assumes there is only one wan interface on a node
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
			if id(interface) == id(self.oob_interface):
				continue
			for exit in self.topology_a_part_of.exit_interfaces:
				if(id(interface.neighbour) == id(exit)):
					return interface
		LOGGER.info(f"Failed to find wan interface for {self.hostname}")
		return None
	
	def paramiko_get_connection(self, ipv4_address: ipaddress = None, user: str = '', password: str = ''):
		'''
		docstring
		'''
		if self.paramiko_connection is not None:
			return self.paramiko_connection
		##########################################################
		if ipv4_address is None:
			if self.oob_interface is not None:
				ipv4_address = self.oob_interface.ipv4_address
		if len(user) == 0:
			user = self.local_user
		if len(password) == 0:
			password = self.local_password
		##########################################################

		LOGGER.debug(f'Attempting paramiko connection to {self.hostname}')
		self.paramiko_connection = paramiko.SSHClient()
		self.paramiko_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Automatically accept unknown keystry:
		try:
			# Establish SSH connection
			self.paramiko_connection.connect(
				hostname=(str)(ipv4_address),
				username=user,
				password=password
			)

			LOGGER.debug(f'Established paramiko connection to {self.hostname}')
			return self.paramiko_connection
		except Exception as e: # TODO
			LOGGER.error(f'Exception establishing paramiko connection to {self.hostname}')
	
	def paramiko_end_connection(self):
		if self.paramiko_connection is not None:
			LOGGER.debug(f'Closing paramiko connection to {self.hostname}')
			self.paramiko_connection.close()
			
	def paramiko_execute_command(self, command: str):
		'''
		Wrapper for exec_command that includes logging.

		Returns: stdout text, stderr text. or None.
		'''
		LOGGER.debug(f'## Paramiko command to {self.hostname} ##\n{command}')
		log_path = GLOBALS.app_path.parent / 'output' / self.hostname / 'paramiko_commmands.log'
		with open(log_path, 'w') as f:
			print(command, file=f)
		stdin, stdout, stderr = self.paramiko_get_connection().exec_command(command)
		import shutil
		import io

		# Create new in-memory buffers
		#stdout_clone = io.BytesIO()
		#stderr_clone = io.BytesIO()

		# Copy original streams into the new buffers
		#shutil.copyfileobj(stdout, stdout_clone)
		#shutil.copyfileobj(stderr, stderr_clone)

		# Reset cloned buffers so they can be read from the beginning
		#stdout_clone.seek(0)
		#stderr_clone.seek(0)
		#stdout.seek(0)
		#stderr.seek(0)

		# debug
		#debug_stream = True
		#if debug_stream:
		#	read_stdout = stdout.read()
		#	read_stderr = stderr.read()
		#	decode_stdout = read_stdout.decode()
		#	decode_stderr = read_stderr.decode()

		# TODO: This may be incorrect
		if stdin is None and stdout is None and stderr is None:
			return None
		else:
			stdout_text = stdout.read().decode().rstrip()
			stderr_text = stderr.read().decode().rstrip()
			if len(stdout_text) != 0:
				LOGGER.debug(f'## Paramiko stdout from {self.hostname} ##\n{stdout_text}')
			if len(stderr_text) != 0:
				LOGGER.debug(f'## Paramiko stderr from {self.hostname} ##\n{stderr_text}')
			return stdout_text, stderr_text