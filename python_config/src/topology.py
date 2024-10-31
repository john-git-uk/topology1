from __future__ import annotations
import logging
from pydantic import BaseModel
from typing import Optional, List, Literal
import ipaddress
LOGGER = logging.getLogger('my_logger')
class Topology(BaseModel):
	class Config:
		debug = True # Enable debug mode
		validate_assignment = True
		arbitrary_types_allowed = True
		from_attributes = True
		fields = {
			'vlans': {'exclude': True},
			'nodes': {'exclude': True},
		}
	domain_name_a: Optional[str]="local"
	domain_name_b: Optional[str]=None
	dns_ipv4_address: Optional[ipaddress.IPv4Address]=None
	exit_interface_main: Optional[Interface]=None
	exit_interface_oob: Optional[Interface]=None
	exit_interface_real_wap: Optional[Interface]=None
	ntp_master: Optional[Interface]=None
	ntp_public: Optional[ipaddress.IPv4Address]=None
	ntp_password: Optional[str]="outoftime"
	#vlans: List[VLAN]=[]
	nodes: List[Node]=[]
	access_segments: List[AccessSegment]=[]
	#def add_vlan(self, vlan: VLAN):
	#	self.vlans.append(vlan)
	def add_node(self, node: Node):
		self.nodes.append(node)
		node.topology_a_part_of=self
	#def get_vlan(self, name: str):
	#	for vlan in self.vlans:
	#		if vlan.name == name:
	#			return vlan
	def get_node(self, name: str):
		for node in self.nodes:
			if node.hostname == name:
				return node
	def get_access_segment(self, name: str):
		for access_segment in self.access_segments:
			if access_segment.name == name:
				return access_segment
	def generate_nodes_interfaces_config(self):
		try:
			LOGGER.info("Generating interfaces config for all nodes")
			LOGGER.debug(f"Here are the nodes in the list: {self.nodes}")
			for node in self.nodes:
				LOGGER.debug(f"Considering generating interfaces config for node: {node.hostname}")
				node.generate_interfaces_config()
				#LOGGER.debug(f"Considering apply config for node using netmiko: {node.hostname}")
				#if(node.machine_data.device_type != "cisco_ios" and node.machine_data.device_type != "cisco_xe"):
				#	continue
				#node.apply_interfaces_config_netmiko()
		except Exception as e:
			LOGGER.error(f"Error generating interfaces config for all nodes: {e}")
			raise
	def generate_nodes_ssh_stubs(self):
		try:
			LOGGER.info("Generating ssh stubs for all nodes")
			LOGGER.debug("Here are the nodes in the list: %s", self.nodes)
			for node in self.nodes:
				LOGGER.debug("Considering generating ssh stubs for node: %s", node.hostname)
				node.generate_ssh_stub()
		except Exception as e:
			LOGGER.error("Error generating ssh stubs for all nodes: %s", e)
			raise
	def choose_linux_node_for_telnet_config(self):
		shortlist = []
		for node in self.nodes:
			if node.machine_data.device_type == "debian" or node.machine_data.device_type == "ubuntu" or node.machine_data.device_type == "alpine":
				shortlist.append(node)
		for index, node in enumerate(shortlist, start=1):
			print(f"{index}. {node.hostname}")
		while True:
			selection = input("Pick a node to configure using telnet:")
			# If selection matches the index of a node exit the loop
			if(selection.isdigit() and 1 <= int(selection) <= len(shortlist)):
				selected_node = shortlist[int(selection) - 1]
				selected_node.config_using_telnet_vconsole()
				break
			else:
				print("Invalid selection.")	
		return None
	def generate_nodes_stp_vlan_config(self):
		try:
			LOGGER.info("Generating stp vlan config for all nodes")
			LOGGER.debug("Here are the nodes in the list: %s", self.nodes)
			for node in self.nodes:
				if(node.machine_data.device_type == "cisco_ios" or node.machine_data.device_type == "cisco_xe"):
					node.generate_stp_vlan_config()
		except Exception as e:
			LOGGER.error("Error generating stp vlan config for all nodes: %s", e)
			raise
	def generate_nodes_fhrp_config(self):
		try:
			LOGGER.info("Generating fhrp config for all nodes")
			LOGGER.debug("Here are the nodes in the list: %s", self.nodes)
			for node in self.nodes:
				if(node.machine_data.device_type == "cisco_ios" or node.machine_data.device_type == "cisco_xe"):
					node.generate_fhrp_config()
		except Exception as e:
			LOGGER.error("Error generating fhrp config for all nodes: %s", e)
			raise
	def generate_multi_config(self):
		try:
			LOGGER.info("Generating multi config for all nodes")
			LOGGER.debug("Here are the nodes in the list: %s", self.nodes)
			for node in self.nodes:
				if(node.machine_data.device_type == "cisco_ios" or node.machine_data.device_type == "cisco_xe"):

					node.generate_ssh_stub()
					node.generate_interfaces_config()
					node.generate_stp_vlan_config()
					node.generate_fhrp_config()
					node.generate_ospf_static_base_config()
					node.generate_dhcp_config()
					node.generate_wan_config()
					node.generate_ntp_config()
		except Exception as e:
			LOGGER.error("Error generating multi config for all nodes: %s", e)
			raise
