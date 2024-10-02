from __future__ import annotations
from project_globals import *
from pydantic import BaseModel, Field, ValidationError, validator
from typing import Optional, List, Dict
import ipaddress
import time
from machine_data import *
import sys
import logging
import os
from pathlib import Path
import netmiko
from netmiko.ssh_autodetect import SSHDetect
from netmiko import ConnectHandler, BaseConnection
import node_methods
import topology_methods
LOGGER = logging.getLogger('my_logger')

#sys.setrecursionlimit(500)  # Set a lower recursion limit

class Interface(BaseModel):
	def __repr__(self):
		return f"Interface(name={self.name})"
	class Config:
		arbitrary_types_allowed = True
		from_attributes = True
		fields = {
			'interfaces': {'exclude': True},
			'neighbour': {'exclude': True},
			'node_a_part_of': {'exclude': True},
			'vlans': {'exclude': True},
		}
	node_a_part_of: Optional["Node"] = None
	neighbour: Optional["Interface"] = None
	name: str
	description: Optional[str]=None
	interfaces: List["Interface"]=[]
	channel_group: Optional[int]=None
	ipv4_address: Optional[ipaddress.IPv4Address]=None
	ipv4_cidr: Optional[int]=None
	ipv6_address: Optional[ipaddress.IPv6Address]=None
	ipv6_cidr: Optional[int]=None
	#Optional[ipv4_address: List[ipaddress.IPv4Address]]=None
	#Optional[ipv4_cidr: List[int]]=None
	#Optional[ipv6_address: List[ipaddress.IPv6Address]]=None
	#Optional[ipv6_cidr: List[int]]=None
	trunk: Optional[bool]=None
	vlans: List["VLAN"]=[]
	def add_vlan(self, vlan: "VLAN"):
		self.vlans.append(vlan)
	def is_vlan_assigned(self, vlan: "VLAN"):
		return vlan in self.vlans
	def connect_to(self, neighbour: "Interface"):
		self.neighbour = neighbour

# Define the VLAN class
class VLAN(BaseModel):
	def __repr__(self):
		return f"VLAN(name={self.name})"
	class Config:
		arbitrary_types_allowed = True
		from_attributes = True
		fields = {
			'main_dhcp_exclusion_start': {'exclude': True},
			'main_dhcp_exclusion_end': {'exclude': True},
			'outreach_dhcp_exclusion_start': {'exclude': True},
			'outreach_dhcp_exclusion_end': {'exclude': True},
		}
	number: int
	name: str

	# Main Site
	main_ipv4_netid: ipaddress.IPv4Address
	main_ipv4_cidr: int
	main_fhrp0_ipv4_address: Optional[ipaddress.IPv4Address] = None
	main_fhrp0_priority: Optional["Interface"] = None # The fhrp member node with the highest priority
	main_fhrp1_ipv6_address: Optional[ipaddress.IPv6Address] = None
	main_fhrp1_priority: Optional["Interface"] = None # The fhrp member node with the highest priority
	main_dhcp_interface: Optional["Interface"] = None
	main_dhcp_exclusion_start: Optional[List[ipaddress.IPv4Address]] = None
	main_dhcp_exclusion_end: Optional[List[ipaddress.IPv4Address]] = None

	# Outreach Site
	outreach_ipv4_netid: Optional[ipaddress.IPv4Address] = None
	outreach_ipv4_cidr: Optional[int] = None
	outreach_dhcp_interface: Optional["Interface"] = None
	outreach_dhcp_exclusion_start: Optional[List[ipaddress.IPv4Address]] = None
	outreach_dhcp_exclusion_end: Optional[List[ipaddress.IPv4Address]] = None

class Node(BaseModel):
	def __repr__(self):
		return f"Node(name={self.hostname})"
	class Config:
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
	machine_data: Optional["MachineData"]=None
	topology_a_part_of: Optional["Topology"]=None
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
		return node_methods.generate_interfaces_config(self)
	def apply_interfaces_config_netmiko(self):
		return node_methods.apply_interfaces_config_netmiko(self)
	def generate_ssh_stub(self):
		return node_methods.generate_ssh_stub(self)
	def config_using_telnet_vconsole(self):
		return node_methods.config_using_telnet_vconsole(self)

class Topology(BaseModel):
	class Config:
		arbitrary_types_allowed = True
		from_attributes = True
		fields = {
			'vlans': {'exclude': True},
			'nodes': {'exclude': True},
		}
	domain_name_a: str
	domain_name_b: str
	exit_interface_main: Optional["Interface"]=None
	exit_interface_oob: Optional["Interface"]=None
	exit_interface_real_wap: Optional["Interface"]=None
	vlans: List[VLAN]
	nodes: List[Node]
	def add_vlan(self, vlan: VLAN):
		self.vlans.append(vlan)
	def add_node(self, node: Node):
		self.nodes.append(node)
		node.topology_a_part_of=self
	def get_vlan(self, name: str):
		for vlan in self.vlans:
			if vlan.name == name:
				return vlan
	def get_node(self, name: str):
		for node in self.nodes:
			if node.hostname == name:
				return node
	def generate_nodes_interfaces_config(self):
		return topology_methods.generate_nodes_interfaces_config(self)
	def generate_nodes_ssh_stubs(self):
		return topology_methods.generate_nodes_ssh_stubs(self)
	def choose_linux_node_for_telnet_config(self):
		return topology_methods.choose_linux_node_for_telnet_config(self)

VLAN.update_forward_refs()
Interface.update_forward_refs()
Node.update_forward_refs()
Topology.update_forward_refs()
def main_structures():
	alpouter_eth_out0=Interface(
		name="eth_out0", # This is a fake interface
		description="",
		ipv4_address="192.168.2.246",
		ipv4_cidr=24
		#ipv6_address=ipaddress.IPv6Address(),
		#ipv6_cidr=128
	)
	alpouter_eth_int0=Interface(
		name="eth_int0", # This is a fake interface
		description="",
		ipv4_address="10.111.111.111",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fff6"),
		ipv6_cidr=128
	)
	topology = Topology(
		domain_name_a = "tapeitup",
		domain_name_b = "private",
		vlans = [],
		nodes = [],
		exit_interface_main=alpouter_eth_int0,
		exit_interface_oob=alpouter_eth_int0,
	)
	alpouter=Node(
		hostname="alpouter",
		machine_data=get_machine_data("alpine"),
		local_user="auto",
		local_password="otua",
		interfaces=[alpouter_eth_int0],
		oob_interface=alpouter_eth_out0,
	)
	topology.add_node(alpouter)
	############################################################################
	vlan_10 = VLAN(
		number=10,
		name="sales",
		main_ipv4_netid="10.133.10.0",
		main_ipv4_cidr=25,
		main_fhrp0_ipv4_address="10.133.10.126",
		main_dhcp_exclusion_start=[ipaddress.ip_address("10.133.10.120")],
		main_dhcp_exclusion_end=[ipaddress.ip_address("10.133.10.126")],
		outreach_ipv4_netid="10.133.10.128",
		outreach_ipv4_cidr=25,
		outreach_dhcp_exclusion_start=[ipaddress.ip_address("10.133.10.250")],
		outreach_dhcp_exclusion_end=[ipaddress.ip_address("10.133.10.255")],
	)
	vlan_20 = VLAN(
		number=20,
		name="guest",
		main_ipv4_netid="10.133.20.0",
		main_ipv4_cidr=23,
		main_fhrp0_ipv4_address="10.133.21.254",
		main_dhcp_exclusion_start=[ipaddress.ip_address("10.133.21.240")],
		main_dhcp_exclusion_end=[ipaddress.ip_address("10.133.21.255")],
		outreach_ipv4_netid="10.133.22.0",
		outreach_ipv4_cidr=24,
		outreach_dhcp_exclusion_start=[ipaddress.ip_address("10.133.22.245")],
		outreach_dhcp_exclusion_end=[ipaddress.ip_address("10.133.22.255")],
	)
	vlan_30 = VLAN(
		number=30,
		name="management",
		main_ipv4_netid="10.133.30.0",
		main_ipv4_cidr=25,
		main_fhrp0_ipv4_address="10.133.30.126",
	)
	vlan_40 = VLAN(
		number=40,
		name="supervisor",
		main_ipv4_netid="10.133.40.0",
		main_ipv4_cidr=25,
		main_fhrp0_ipv4_address="10.133.40.126",
	)
	vlan_50 = VLAN(
		number=50,
		name="voice",
		main_ipv4_netid="10.133.50.0",
		main_ipv4_cidr=25,
	)
	vlan_60 = VLAN(
		number=60,
		name="guest-services",
		main_ipv4_netid="10.133.60.0",
		main_ipv4_cidr=24,
		main_fhrp0_ipv4_address="10.133.60.254",
	)
	vlan_70 = VLAN(
			number=70,
			name="internal-services",
			main_ipv4_netid="10.133.70.0",
			main_ipv4_cidr=24,
			main_fhrp0_ipv4_address="10.133.70.254",
	)
	vlan_80 = VLAN(
			number=80,
			name="accounting",
			main_ipv4_netid="10.133.80.0",
			main_ipv4_cidr=24,
			main_fhrp0_ipv4_address="10.133.80.254",
	)
	vlan_250 = VLAN(
			number=250,
			name="oob",
			main_ipv4_netid="10.133.250.0",
			main_ipv4_cidr=24,
	)
	topology.add_vlan(vlan_10)
	topology.add_vlan(vlan_20)
	topology.add_vlan(vlan_30)
	topology.add_vlan(vlan_40)
	topology.add_vlan(vlan_50)
	topology.add_vlan(vlan_60)
	topology.add_vlan(vlan_70)
	topology.add_vlan(vlan_80)
	topology.add_vlan(vlan_250)
	############################################################################
	radius_server_interface_eth1=Interface(
		name="eth1",
		ipv4_address="10.131.70.251",
		ipv4_cidr=24
	)
	radius_server_interface_eth2=Interface(
		name="eth2",
		ipv4_address="192.168.250.101",
		ipv4_cidr=24
	)
	radius_server=Node(
		hostname="radius_server",
		machine_data=get_machine_data("debian"),
		local_user="root",
		local_password="",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=radius_server_interface_eth2,
	)
	radius_server.config_path=os.path.abspath("../node_config/server/radius_server")
	LOGGER.debug("radius_server.config_path: "+radius_server.config_path)
	radius_server.config_copying_paths = [
		{"source": radius_server.config_path+"/clients.conf", "dest": "/etc/freeradius/3.0/clients.conf"},
		{"source": radius_server.config_path+"/authorize", "dest": "/etc/freeradius/3.0/mods-config/files/authorize"},
		{"source": radius_server.config_path+"/networkconfig.sh", "dest": "/sbin/scripts/networkconfig.sh"},
		{"source": radius_server.config_path+"/sshd_config", "dest": "/etc/ssh/sshd_config"},
		{"source": radius_server.config_path+"/starter.sh", "dest": "/sbin/scripts/starter.sh"},
	]
	topology.add_node(radius_server)
	############################################################################

	ldap_server_interface_eth1=Interface(
		name="eth1",
		ipv4_address="10.131.70.250",
		ipv4_cidr=24
	)
	ldap_server_interface_eth2=Interface(
		name="eth2",
		ipv4_address="192.168.250.102",
		ipv4_cidr=24
	)
	ldap_server=Node(
		hostname="ldap_server",
		machine_data=get_machine_data("debian"),
		local_user="root",
		local_password="",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=ldap_server_interface_eth2,
	)
	ldap_server.config_path=os.path.abspath("../node_config/server/ldap_server")
	ldap_server.config_copying_paths = [
		{"source": ldap_server.config_path+"/runonce.conf", "dest": "/sbin/scripts/runonce.sh"},
		{"source": ldap_server.config_path+"/networkconfig.sh", "dest": "/sbin/scripts/networkconfig.sh"},
		{"source": ldap_server.config_path+"/sshd_config", "dest": "/etc/ssh/sshd_config"},
		{"source": ldap_server.config_path+"/starter.sh", "dest": "/sbin/scripts/starter.sh"},
		{"source": ldap_server.config_path+"/config.php", "dest": "/etc/phpldapadmin/config.php"},
		{"source": ldap_server.config_path+"/base.ldif", "dest": "/root/base.ldif"},
		{"source": ldap_server.config_path+"/ldap_setup.sh", "dest": "/sbin/scripts/ldap_setup.sh"},
		{"source": ldap_server.config_path+"/ldap_build.sh", "dest": "/sbin/scripts/ldap_build.sh"},
		{"source": ldap_server.config_path+"/ldap_build.sh", "dest": "/sbietc/nslcd.conf"},
		{"source": ldap_server.config_path+"/ldap_build.sh", "dest": "/etc/nslcd.conf"},
		{"source": ldap_server.config_path+"/ldap_build.sh", "dest": "/etc/nsswitch.conf"},
		{"source": ldap_server.config_path+"/logging.ldif", "dest": "/root/logging.ldif"}
	]
	topology.add_node(ldap_server)
	############################################################################

	aaa_server_interface_eth1=Interface(
		name="eth1",
		ipv4_address="10.131.70.251",
		ipv4_cidr=24
	)
	aaa_server_interface_eth2=Interface(
		name="eth2",
		ipv4_address="192.168.250.101",
		ipv4_cidr=24
	)
	aaa_server=Node(
		hostname="aaa_server",
		machine_data=get_machine_data("ubuntu"),
		local_user="root",
		local_password="",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=aaa_server_interface_eth2,
	)
	aaa_server.config_path=os.path.abspath("../node_config/server/aaa_server")
	aaa_server.config_copying_paths = [
		{"source": aaa_server.config_path+"/clients.conf", "dest": "/etc/freeradius/3.0/clients.conf"},
		{"source": aaa_server.config_path+"/authorize", "dest": "/etc/freeradius/3.0/mods-config/files/authorize"},
		{"source": aaa_server.config_path+"/tac_plus.conf", "dest": "/etc/tacacs+/tac_plus.conf"},
		{"source": aaa_server.config_path+"/networkconfig.sh", "dest": "/sbin/scripts/networkconfig.sh"},
		{"source": aaa_server.config_path+"/sshd_config", "dest": "/etc/ssh/sshd_config"},
		{"source": aaa_server.config_path+"/starter.sh", "dest": "/sbin/scripts/starter.sh"},
	]
	topology.add_node(aaa_server)
	############################################################################
	prox1_interface_vi_oob = {
		"name": "vi_oob",
		"ipv4_address": "192.168.2.239",
		"ipv4_cidr": 24,
		"mac_address": "52:54:00:24:15:df"
	}

	prox1_interface_vi_vlan60 = {
		"name": "vi_vlan60",
		"ipv4_address": None,  # No IPv4 address assigned
		"ipv6_address": "fe80::5054:ff:fe9e:ab06/64",
		"mac_address": "52:54:00:9e:ab:08"
	}

	prox1_interface_vi_vlan70 = {
		"name": "vi_vlan70",
		"ipv4_address": "192.168.70.231",
		"ipv4_cidr": 24,
		"ipv6_address": "fe80::5054:ff:fe9e:ab08/64",
		"mac_address": "52:54:00:9e:ab:08"
	}
	prox1=Node(
		hostname="prox1",
		machine_data=get_machine_data("proxmox"),
		local_user="root",
		local_password="toorp",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=prox1_interface_vi_oob,
	)
	prox1.config_path=os.path.abspath("../node_config/server/prox1")
	prox1.config_copying_paths = []
	topology.add_node(prox1)
	return topology
def main_relations(topology: Topology):
	topology.get_vlan("sales").main_fhrp0_priority=topology.get_node("SW3"),
	topology.get_vlan("sales").main_dhcp_interface=topology.get_node("SW3").get_interface("l0"),
	topology.get_vlan("sales").outreach_dhcp_interface=topology.get_node("SW3").get_interface("l0"),

	topology.get_vlan("guest").main_fhrp0_priority=topology.get_node("SW4"),
	topology.get_vlan("guest").main_dhcp_interface=topology.get_node("SW3").get_interface("l0"),
	topology.get_vlan("guest").outreach_dhcp_interface=topology.get_node("SW3").get_interface("l0"),

	topology.get_vlan("management").main_fhrp0_priority=topology.get_node("SW4"),
	topology.get_vlan("supervisor").main_fhrp0_priority=topology.get_node("SW3"),
	topology.get_vlan("guest-services").main_fhrp0_priority=topology.get_node("SW3"),
	topology.get_vlan("internal-services").main_fhrp0_priority=topology.get_node("SW4"),
	topology.get_vlan("accounting").main_fhrp0_priority=topology.get_node("SW4"),
	LOGGER.debug(str(len(topology.nodes)))
