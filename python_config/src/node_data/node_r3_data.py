from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def r3_Structures(topology: Topology):
	LOGGER.debug("Loading r3 Structures")

	for segs in topology.access_segments:
		if(segs.name == "outreach"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	machine_data=get_machine_data("Cisco IOU L3 17.12.1")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_r3_i1=Interface(
		name ="0/0",
		interface_type="ethernet",
		description="",
		ipv4_address="10.111.10.30",
		ipv4_cidr=31,
		ospf_participant=False,
		ospf_passive=True,
		#ipv6_address=""
	)
	node_r3_i2=Interface(
		name ="0/1",
		interface_type="ethernet",
		description="Connected to sw7 via Subinterfaces",
		ospf_participant=False,
		ospf_passive=True,
		#ipv4_address="",
		#ipv4_cidr=31,
		#ipv6_address=""
	)
	node_r3_i3=Interface(
		name ="0/1.10",
		interface_type="ethernet",
		description="",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.10.254",
		ipv4_cidr=25,
	)
	node_r3_i4=Interface(
		name ="0/1.20",
		interface_type="ethernet",
		description="",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.22.254",
		ipv4_cidr=24,
	)
	node_r3_i5=Interface(
		name ="0/1.30",
		interface_type="ethernet",
		description="",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.30.254",
		ipv4_cidr=25,
	)
	node_r3_i6=Interface(
		name ="0/1.40",
		interface_type="ethernet",
		description="",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.40.254",
		ipv4_cidr=25,
	)
	node_r3_i7=Interface(
		name ="0/3",
		interface_type="ethernet",
		description="Out of band",
		ospf_participant=False,
		ospf_passive=True,
		ipv4_address="192.168.250.3",
		ipv4_cidr=24,
	)
	node_r3_i8=Interface(
		name ="0",
		interface_type="loopback",
		description="l0",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.2.3",
		ipv4_cidr=32,
		#ipv6_address=""
	)
	node_r3_i9=Interface(
		name ="0",
		interface_type="tunnel",
		description="tunnel to r1 via IPsec",
		ospf_participant=True,
		ospf_passive=False,
		ipv4_address="10.133.2.69",
		ipv4_cidr=31,
	)
	node_r3_i10=Interface(
		name ="1",
		interface_type="tunnel",
		description="tunnel to r2 via IPsec",
		ospf_participant=True,
		ospf_passive=False,
		ipv4_address="10.133.2.71",
		ipv4_cidr=31,
	)
	node_r3=Node(
		hostname ="r3",
		local_user=GLOBALS.r3_username,
		local_password=GLOBALS.r3_password,
		machine_data=machine_data,
		oob_interface=node_r3_i7,
		identity_interface=node_r3_i8,
		additional_config=r3_additional_config
	)
	node_r3.add_interface(node_r3_i1)
	node_r3.add_interface(node_r3_i2)
	node_r3.add_interface(node_r3_i3)
	node_r3.add_interface(node_r3_i4)
	node_r3.add_interface(node_r3_i5)
	node_r3.add_interface(node_r3_i6)
	node_r3.add_interface(node_r3_i7)
	node_r3.add_interface(node_r3_i8)
	node_r3.add_interface(node_r3_i9)
	node_r3.add_interface(node_r3_i10)
	access_segment.nodes.append(node_r3)
	node_r3.access_segment=access_segment
	topology.add_node(node_r3)
def r3_relations(topology: Topology):
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
	######################################################################
	LOGGER.debug("Loading r3 Relations")
	r3_node.get_interface("ethernet","0/0").connect_to(topology.get_exit_interface("exit_r3"))
	r3_node.get_interface("ethernet","0/1").connect_to(sw7_node.get_interface("ethernet","0/0"))
	r3_node.get_interface("ethernet","0/1.10").connect_to(sw7_node.get_interface("ethernet","0/0"))
	r3_node.get_interface("ethernet","0/1.20").connect_to(sw7_node.get_interface("ethernet","0/0"))
	r3_node.get_interface("ethernet","0/1.30").connect_to(sw7_node.get_interface("ethernet","0/0"))
	r3_node.get_interface("ethernet","0/1.40").connect_to(sw7_node.get_interface("ethernet","0/0"))
	r3_node.get_interface("ethernet","0/3").connect_to(topology.get_exit_interface('exit_oob'))
	if r1_node.machine_data.gigabit_naming:
		r3_node.get_interface("tunnel","0").tunnel_destination=topology.get_node("r1").get_interface("gigabitethernet","2")
	else:
		r3_node.get_interface("tunnel","0").tunnel_destination=topology.get_node("r1").get_interface("ethernet","0/1")
	r3_node.get_interface("tunnel","1").tunnel_destination=topology.get_node("r2").get_interface("ethernet","0/1")
	r3_node.get_interface("tunnel","0").connect_to(topology.get_node("r1").get_interface("tunnel","0"))
	r3_node.get_interface("tunnel","1").connect_to(topology.get_node("r2").get_interface("tunnel","0"))

def r3_additional_config(node: Node):
	if node.hostname != 'r3':
		LOGGER.error('{node.hostname} additional config was passed another node.')
		return
	LOGGER.debug(f'{node.hostname} has no additional config at the moment.')
	return