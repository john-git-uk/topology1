from __future__ import annotations
import logging
from pydantic import BaseModel
from typing import Optional, List, Literal
from access_control import Access_Control
from project_globals import GLOBALS
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
	#exit_interface_main: Optional[Interface]=None
	#exit_interface_oob: Optional[Interface]=None
	#exit_interface_real_wap: Optional[Interface]=None
	exit_interfaces: List[Interface]=[]
	ntp_master: Optional[Interface]=None
	ntp_public: Optional[ipaddress.IPv4Address]=None
	ntp_password: Optional[str]="outoftime"
	dns_private: List[Interface]=[]
	dns_upstream: List[ipaddress]=[]
	certificate_authorities: List[Interface]=[]
	nodes: List[Node]=[]
	access_segments: List[AccessSegment]=[]
	access_controls: List[Access_Control]=[]
	def add_node(self, node: Node):
		self.nodes.append(node)
		node.topology_a_part_of=self
	def get_node(self, name: str):
		for node in self.nodes:
			if node.hostname == name:
				return node
	def get_access_segment(self, name: str):
		for access_segment in self.access_segments:
			if access_segment.name == name:
				return access_segment
	def get_exit_interface(self, name: str):
		for interface in self.exit_interfaces:
			if interface.name == name:
				return interface
		LOGGER.error(f"No topology exit interface found with name: {name}")
		return None
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
				#if(node.machine_data.device_type == "cisco_ios" or node.machine_data.device_type == "cisco_xe"):

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
	def make_genie_yaml(self):
		import yaml
		data = {
			"testbed": {
				"name": "My_Network",
				"credentials": {
					"default": {
						"username": "your_username",
						"password": "your_password"
					},
					"enable": {
						"password": "your_enable_password"
					}
				}
			},
			"devices":{}
		}
		
		# add devices from topology.nodes
		for node in self.nodes:
			if node.machine_data.device_type == 'cisco_xe':
				os='iosxe'
			elif node.machine_data.device_type == 'cisco_ios':
				os='ios'
			else:
				continue
			if node.machine_data.category == 'router':
				vtype = "router"
			else:
				vtype = "switch"
			data["devices"][node.hostname] = {
				"os": os,
				"type": vtype,
				"connections": {
					"cli": {
						"protocol": "ssh",
						"ip": (str)(node.oob_interface.ipv4_address),
						}
					},
					"credentials": {
						"default": {
							"username": node.local_user,
							"password": node.local_password
						},
						"enable": {
							"password": node.local_password
						}
					}
				}
			if len(node.machine_data.ssh_options) == 4:
				data["devices"][node.hostname]["connections"]["cli"]["ssh_options"] = (
					f"-o {node.machine_data.ssh_options[0]} -o {node.machine_data.ssh_options[1]}" 
					+f" -o {node.machine_data.ssh_options[2]} -o {node.machine_data.ssh_options[3]}"
				)


		# Write the data to a YAML file
		with open(GLOBALS.testbed_path, "w") as file:
			yaml.dump(data, file, default_flow_style=False)

		print("YAML file 'testbed.yaml' has been created.")