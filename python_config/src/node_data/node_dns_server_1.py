from __future__ import annotations
import paramiko
from handle_debian import commands_packages_essential, commands_packages_ldap_client, \
 commands_packages_pi_hole, commands_config_pi_hole, commands_config_ldap_client
import logging
from convert import get_escaped_string, get_chunky_hex, base64_encode_string
from interface import Interface
from node import Node
from handle_proxmox import Container, execute_proxnode_commands, start_container, wait_for_container_ping_debian, wait_for_container_running
import aiohttp
import asyncio
import pihole as ph
import base64
import time
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def dns_server_1_structures(topology: Topology):
	from machine_data import get_machine_data

	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	dns_server1_i1 = Interface(
		name="eth0",
		interface_type="ethernet",
		description="oob",
		ipv4_address="192.168.250.229",
		ipv4_cidr=24
	)
	dns_server1_i2 = Interface(
		name="eth1",
		interface_type="ethernet",
		ipv4_address="10.133.60.249",
		ipv4_cidr=24
	)
	dns_server1_i3 = Interface(
		name="eth2",
		interface_type="ethernet",
		ipv4_address="10.133.70.249",
		ipv4_cidr=24
	)
	dns_server1_i4 = Interface(
		name="eth3",
		description="management",
		interface_type="ethernet",
		ipv4_address="10.133.30.122",
		ipv4_cidr=25
	)
	dns_server1 = Node(
		hostname="dns-server-1",
		machine_data=get_machine_data("debian"),
		oob_interface=dns_server1_i1,
		identity_interface=dns_server1_i2,
		local_user=GLOBALS.dns_server_1_username,
		local_password=GLOBALS.dns_server_1_password,
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
	dns_server1.add_interface(dns_server1_i3)
	dns_server1.add_interface(dns_server1_i4)
	prox1.topology_a_part_of.add_node(dns_server1)
	prox1.add_container(dns_server1_container)
	access_segment.nodes.append(dns_server1)
	dns_server1.access_segment = access_segment

def dns_server_1_relations(topology: Topology):
	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	dns_server_1 = None
	dns_server_1 = topology.get_node("dns-server-1")
	
	if(dns_server_1 is None):
		raise Exception("dns_server_1 is None")

	dns_server_1.get_interface("ethernet","eth0").connect_to(prox1.get_interface("bridge","oob_hitch"))
	dns_server_1.get_interface("ethernet","eth1").connect_to(prox1.get_interface("bridge","vmbr60"))
	dns_server_1.get_interface("ethernet","eth2").connect_to(prox1.get_interface("bridge","vmbr70"))
	dns_server_1.get_interface("ethernet","eth3").connect_to(prox1.get_interface("bridge","vmbr30"))

def dns_server_1_config(dns_server_1: Node):
	topology = None
	prox1 = None
	container = None
	topology = dns_server_1.topology_a_part_of
	if topology is None:
		LOGGER.error("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		LOGGER.error("prox1 does not exist! Did you try to load in the wrong order?")
		return
	container = prox1.get_container(dns_server_1.hostname)
	if container is None:
		LOGGER.error("container is None")
		return
	if len(topology.dns_upstream) == 0:
		LOGGER.error(f"topology.dns_upstream is empty. Configuring {dns_server_1.hostname} requires at least one upstream DNS server")
		return
	if not wait_for_container_running(prox1, container, 30):
		LOGGER.error(f"Container {dns_server_1.hostname} did not start in time")
		return
	commands = []
	for upstream in topology.dns_upstream:
		commands += [
			"rm -rf /etc/resolv.conf",
			f"echo 'nameserver {str(upstream)}' >> /etc/resolv.conf",
		]
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands)
	if not wait_for_container_ping_debian(prox1, container, 30):
		LOGGER.error(f"Container {dns_server_1.hostname} cannot contact website")
		return
	
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands_packages_essential(dns_server_1))
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands_packages_ldap_client(dns_server_1))
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands_packages_pi_hole(dns_server_1))
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands_config_pi_hole(dns_server_1))
