from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def r2_Structures(topology: Topology):
	LOGGER.debug("Loading r2 Structures")
	machine_data=get_machine_data("Cisco IOU L3 17.12.1")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_r2_i1=Interface(
		name ="0/0",
		interface_type="ethernet",
		description="Connected to sw4",
		ipv4_address="10.133.2.66",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
		#ipv6_ipv4_address=""
	)
	node_r2_i2=Interface(
		name ="0/1",
		interface_type="ethernet",
		description="Connected to ISP",
		ipv4_address="10.111.10.20",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=True,
		#ipv6_ipv4_address=""
	)
	node_r2_i3=Interface(
		name ="0/2",
		interface_type="ethernet",
		description="Connected to sw3",
		ipv4_address="10.133.2.74",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
		#ipv6_address=""
	)
	node_r2_i4=Interface(
		name ="0/3",
		interface_type="ethernet",
		description="Out of band",
		ipv4_address="192.168.250.2",
		ospf_participant=False,
		ospf_passive=True,
		ipv4_cidr=24,
	)
	node_r2_i5=Interface(
		name ="0",
		interface_type="loopback",
		description="l0",
		ipv4_address="10.133.2.2",
		ipv4_cidr=32,
		ospf_participant=True,
		ospf_passive=True,
		#ipv6_address=""
	)
	node_r2_i6=Interface(
		name ="0",
		interface_type="tunnel",
		description="tunnel to r3 via IPsec",
		ipv4_address="10.133.2.70",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
		#ipv6_address=""
	)

	node_r2=Node(
		hostname ="r2",
		local_user=GLOBALS.r2_username,
		local_password=GLOBALS.r2_password,
		machine_data=machine_data,
		oob_interface=node_r2_i4,
		identity_interface=node_r2_i5,
		additional_config=r2_additional_config
	)
	node_r2.add_interface(node_r2_i1)
	node_r2.add_interface(node_r2_i2)
	node_r2.add_interface(node_r2_i3)
	node_r2.add_interface(node_r2_i4)
	node_r2.add_interface(node_r2_i5)
	node_r2.add_interface(node_r2_i6)
	topology.add_node(node_r2)

def r2_relations(topology: Topology):
	r1_node = topology.get_node("r1")
	if r1_node is None:
		LOGGER.error("r1 node not found")
		return
	r2_node = topology.get_node("r2")
	if r2_node is None:
		LOGGER.error("r2 node not found")
		return
	r3_node = topology.get_node("r3")
	if r3_node is None:
		LOGGER.error("r3 node not found")
		return
	sw1_node = topology.get_node("sw1")
	if sw1_node is None:
		LOGGER.error("sw1 node not found")
		return
	sw2_node = topology.get_node("sw2")
	if sw2_node is None:
		LOGGER.error("sw2 node not found")
		return
	sw3_node = topology.get_node("sw3")
	if sw3_node is None:
		LOGGER.error("sw3 node not found")
		return
	sw4_node = topology.get_node("sw4")
	if sw4_node is None:
		LOGGER.error("sw4 node not found")
		return
	sw5_node = topology.get_node("sw5")
	if sw5_node is None:
		LOGGER.error("sw5 node not found")
		return
	sw6_node = topology.get_node("sw6")
	if sw6_node is None:
		LOGGER.error("sw6 node not found")
		return
	sw7_node = topology.get_node("sw7")
	if sw7_node is None:
		LOGGER.error("sw7 node not found")
		return
	################################################################
	LOGGER.debug("Loading r2 Relations")
	r2_node.get_interface("ethernet","0/0").connect_to(topology.get_node("sw4").get_interface("ethernet","1/3"))
	r2_node.get_interface("ethernet","0/1").connect_to(topology.get_exit_interface("exit_r2"))
	r2_node.get_interface("ethernet","0/2").connect_to(topology.get_node("sw3").get_interface("ethernet","1/2"))
	r2_node.get_interface("ethernet","0/3").connect_to(topology.get_exit_interface('exit_oob'))
	r2_node.get_interface("tunnel","0").tunnel_destination=(topology.get_node("r3").get_interface("ethernet","0/0"))
	r2_node.get_interface("tunnel","0").connect_to(topology.get_node("r3").get_interface("tunnel","1"))

def r2_additional_config(node: Node):
	if node.hostname != 'r2':
		LOGGER.error('{node.hostname} additional config was passed another node.')
		return
	LOGGER.debug(f'{node.hostname} has no additional config at the moment.')
	return