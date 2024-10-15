from __future__ import annotations
import paramiko
from handle_debian import *
import logging
from convert import get_escaped_string
from interface import Interface
from node import Node
from handle_proxmox import Container, execute_proxnode_commands
LOGGER = logging.getLogger('my_logger')
def dns_server_1_structures(topology: Topology):
	from machine_data import get_machine_data

	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	dns_server1_i1 = Interface(
		name="eth0",
		ipv4_address="192.168.2.229",
		ipv4_cidr=24
	)
	dns_server1_i2 = Interface(
		name="eth1",
		ipv4_address="10.133.60.249",
		ipv4_cidr=24
	)
	dns_server1 = Node(
		hostname="dns-server-1",
		machine_data=get_machine_data("debian"),
		oob_interface=dns_server1_i1,
		local_user="root",
		local_password="12345",
		hypervisor_telnet_port=0,
	)
	dns_server1_container = Container(
		ctid=203,
		template="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
		memory=512,
		cores=1,
		rootfs="local:8",
		resource_pool = "default",
		disk_size=8,
		node_a_part_of=prox1,
		node_data=dns_server1,
	)
	dns_server1.add_interface(dns_server1_i1)
	dns_server1.add_interface(dns_server1_i2)
	prox1.topology_a_part_of.add_node(dns_server1)
	prox1.add_container(dns_server1_container)

def dns_server_1_relations(topology: Topology):
	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	dns_server_1 = None
	dns_server_1 = topology.get_node("dns-server-1")
	
	if(dns_server_1 is None):
		raise Exception("dns_server_1 is None")

	dns_server_1.get_interface("eth0").connect_to(prox1.get_interface("oob_hitch"))
	dns_server_1.get_interface("eth1").connect_to(prox1.get_interface("vmbr60"))

def dns_server_1_config(dns_server_1: Node):
	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

def packages_time_dns_server_1(dns_server_1: Node):
	topology = None
	prox1 = None
	container = None
	topology = dns_server_1.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	container = prox1.get_container(dns_server_1.hostname)
	if container is None:
		raise ValueError("container is None")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	
	LOGGER.warning("Packages and time for dns_server_1 not implemented yet.")

def configure_dns_server_1(dns_server_1: Node):
	topology = None
	prox1 = None
	container = None
	topology = dns_server_1.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	container = prox1.get_container(dns_server_1.hostname)
	if container is None:
		raise ValueError("container is None")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	
	LOGGER.warning("Configure for dns_server_1 not implemented yet.")

