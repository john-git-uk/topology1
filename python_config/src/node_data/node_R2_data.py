from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def R2_Structures(topology: Topology):
	LOGGER.debug("Loading R2 Structures")
	machine_data=get_machine_data("Cisco IOU L3 17.12.1")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_R2_i1=Interface(
		name="0/0",
		interface_type="ethernet",
		description="Connected to SW4",
		ipv4_address="10.133.2.66",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
		#ipv6_ipv4_address=""
	)
	node_R2_i2=Interface(
		name="0/1",
		interface_type="ethernet",
		description="Connected to ISP",
		ipv4_address="10.111.10.20",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=True,
		#ipv6_ipv4_address=""
	)
	node_R2_i3=Interface(
		name="0/2",
		interface_type="ethernet",
		description="Connected to SW3",
		ipv4_address="10.133.2.74",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
		#ipv6_address=""
	)
	node_R2_i4=Interface(
		name="0/3",
		interface_type="ethernet",
		description="Out of band",
		ipv4_address="192.168.250.2",
		ospf_participant=False,
		ospf_passive=True,
		ipv4_cidr=24,
	)
	node_R2_i5=Interface(
		name="0",
		interface_type="loopback",
		description="l0",
		ipv4_address="10.133.2.2",
		ipv4_cidr=32,
		ospf_participant=True,
		ospf_passive=True,
		#ipv6_address=""
	)
	node_R2_i6=Interface(
		name="0",
		interface_type="tunnel",
		description="tunnel to R3 via IPsec",
		ipv4_address="10.133.2.70",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
		#ipv6_address=""
	)

	node_R2=Node(
		hostname="R2",
		local_user=GLOBALS.r2_username,
		local_password=GLOBALS.r2_password,
		machine_data=machine_data,
		oob_interface=node_R2_i4,
		identity_interface=node_R2_i5,
	)
	node_R2.add_interface(node_R2_i1)
	node_R2.add_interface(node_R2_i2)
	node_R2.add_interface(node_R2_i3)
	node_R2.add_interface(node_R2_i4)
	node_R2.add_interface(node_R2_i5)
	node_R2.add_interface(node_R2_i6)
	topology.add_node(node_R2)
def R2_relations(topology: Topology):
	LOGGER.debug("Loading R2 Relations")
	topology.get_node("R2").get_interface("ethernet","0/0").connect_to(topology.get_node("SW4").get_interface("ethernet","1/3"))
	topology.get_node("R2").get_interface("ethernet","0/1").connect_to(topology.get_exit_interface("exit_r2"))
	topology.get_node("R2").get_interface("ethernet","0/2").connect_to(topology.get_node("SW3").get_interface("ethernet","1/2"))
	topology.get_node("R2").get_interface("ethernet","0/3").connect_to(topology.get_exit_interface('exit_oob'))
	topology.get_node("R2").get_interface("tunnel","0").tunnel_destination=(topology.get_node("R3").get_interface("ethernet","0/0"))
	topology.get_node("R2").get_interface("tunnel","0").connect_to(topology.get_node("R3").get_interface("tunnel","1"))