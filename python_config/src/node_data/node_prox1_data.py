from __future__ import annotations
import paramiko
from handle_debian import *
import logging
from convert import get_escaped_string, get_chunky_hex, base64_encode_string
from interface import Interface
from node import Node
from handle_proxmox import Container, execute_proxnode_commands, start_container, wait_for_container_ping_debian, wait_for_container_running
from machine_data import get_machine_data
import os
LOGGER = logging.getLogger('my_logger')

def prox1_structures(topology: Topology):
	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	prox1_interface_oob_hitch = Interface (
		name= "oob_hitch",
		interface_type="bridge",
		ipv4_address= "192.168.250.239",
		ipv4_cidr= 24,
	)
	prox1_interface_vmbr30 = Interface (
		name= "vmbr30",
		interface_type="bridge",
		ipv4_address= "10.133.30.125",
		ipv4_cidr= 25,
		vlans=[access_segment.get_vlan("management")],
	)
	prox1_interface_vmbr60 = Interface (
		name= "vmbr60",
		interface_type="bridge",
		ipv4_address= "10.133.60.248",
		ipv4_cidr= 24,
		vlans=[access_segment.get_vlan("guest-services")],
	)
	prox1_interface_vmbr70 = Interface (
		name= "vmbr70",
		interface_type="bridge",
		ipv4_address= "10.133.70.250",
		ipv4_cidr= 24,
		vlans=[access_segment.get_vlan("internal-services")],
	)
	prox1_interface_enp1s0 = Interface (
		name= "enp1s0",
		interface_type="ethernet",
	)
	prox1_interface_enp2s0 = Interface (
		name= "enp2s0",
		interface_type="ethernet",
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services")
		],
	)
	prox1_interface_enp2s0_30 = Interface (
		name= "enp2s0.30",
		interface_type="ethernet",
		description="Connected to SW3",
		vlans=[access_segment.get_vlan("management")],
	)
	prox1_interface_enp2s0_60 = Interface (
		name= "enp2s0.60",
		interface_type="ethernet",
		description="Connected to SW3",
		vlans=[access_segment.get_vlan("guest-services")],
	)
	prox1_interface_enp2s0_70 = Interface (
		name= "enp2s0.70",
		interface_type="ethernet",
		description="Connected to SW3",
		vlans=[access_segment.get_vlan("internal-services")],
	)
	prox1=Node(
		hostname="prox1",
		machine_data=get_machine_data("proxmox"),
		local_user="root",
		local_password="toorp",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=prox1_interface_oob_hitch,
		identity_interface=prox1_interface_vmbr30,
	)
	prox1.add_interface(prox1_interface_oob_hitch)
	prox1.add_interface(prox1_interface_vmbr30)
	prox1.add_interface(prox1_interface_vmbr60)
	prox1.add_interface(prox1_interface_vmbr70)
	prox1.add_interface(prox1_interface_enp1s0)
	prox1.add_interface(prox1_interface_enp2s0)
	prox1.add_interface(prox1_interface_enp2s0_30)
	prox1.add_interface(prox1_interface_enp2s0_60)
	prox1.add_interface(prox1_interface_enp2s0_70)
	prox1.config_path=os.path.abspath("../node_config/server/prox1")
	prox1.config_copying_paths = []
	topology.add_node(prox1)

def prox1_relations(topology: Topology):
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise Exception("prox1 is None")
	if prox1.machine_data != get_machine_data("proxmox"):
		raise Exception("prox1.machine_data != get_machine_data('proxmox')")
	
	# TODO: Not using this?
	ldap_server_1 = prox1.get_container("ldap-server-1")
	ldap_server_1 = prox1.get_container("radius-server-1")
	dns_server_1 = prox1.get_container("dns-server-1")
	
	topology.get_node("prox1").get_interface("ethernet","enp1s0").connect_to(topology.get_exit_interface('exit_oob'))
	topology.get_node("prox1").get_interface("ethernet","enp2s0").connect_to(topology.get_node("SW6").get_interface("ethernet","2/0"))
	topology.get_node("prox1").get_interface("bridge","oob_hitch").connect_to(prox1.get_interface("ethernet","enp1s0"))
	topology.get_node("prox1").get_interface("bridge","vmbr30").connect_to(prox1.get_interface("ethernet","enp2s0.30"))
	topology.get_node("prox1").get_interface("bridge","vmbr60").connect_to(prox1.get_interface("ethernet","enp2s0.60"))
	topology.get_node("prox1").get_interface("bridge","vmbr70").connect_to(prox1.get_interface("ethernet","enp2s0.70"))
