from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
LOGGER = logging.getLogger('my_logger')
def SW6_Structures(topology: Topology):
	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return
	LOGGER.debug("Loading SW1 Structures")
	machine_data=get_machine_data("viosl2-adventerprisek9-m.ssa.high_iron_20200929")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_SW6_i1=Interface(
		name="e0/0",
		channel_group=2
	)
	node_SW6_i2=Interface(
		name="e0/1",
		channel_group=1
	)
	node_SW6_i3=Interface(
		name="e0/2",
		trunk=False,
		vlans=[access_segment.get_vlan("management")]
	)
	node_SW6_i4=Interface(
		name="e0/3",
		trunk=False,
		vlans=[access_segment.get_vlan("internal-services")]
	)
	node_SW6_i5=Interface(
		name="e1/0",
		trunk=False,
		vlans=[access_segment.get_vlan("guest-services")]
	)
	node_SW6_i6=Interface(
		name="e1/1",
		channel_group=2
	)
	node_SW6_i7=Interface(
		name="e1/2",
		channel_group=1
	)
	node_SW6_i8=Interface(
		name="e1/3",
		trunk=False,
		vlans=[access_segment.get_vlan("guest-services")]
	)
	node_SW6_i9=Interface(
		name="e5/3",
		description="out of band",
		ipv4_address="192.168.250.56",
		ipv4_cidr=24
	)
	node_SW6_i10=Interface(
		name="l0",
		description="",
		ipv4_address="10.133.2.18",
		ipv4_cidr=32
	)
	node_SW6_i11=Interface(
		name="port 1",
		interfaces=[node_SW6_i2, node_SW6_i7],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		]
	)
	node_SW6_i12=Interface(
		name="port 2",
		interfaces=[node_SW6_i1, node_SW6_i6],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		]
	)
	node_SW6 = Node(
		hostname="SW6",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_SW6_i9
	)
	node_SW6.add_interface(node_SW6_i1)
	node_SW6.add_interface(node_SW6_i2)
	node_SW6.add_interface(node_SW6_i3)
	node_SW6.add_interface(node_SW6_i4)
	node_SW6.add_interface(node_SW6_i5)
	node_SW6.add_interface(node_SW6_i6)
	node_SW6.add_interface(node_SW6_i7)
	node_SW6.add_interface(node_SW6_i8)
	node_SW6.add_interface(node_SW6_i9)
	node_SW6.add_interface(node_SW6_i10)
	node_SW6.add_interface(node_SW6_i11)
	node_SW6.add_interface(node_SW6_i12)
	topology.add_node(node_SW6)
	access_segment.nodes.append(node_SW6)
def SW6_relations(topology: Topology):
	LOGGER.debug("Loading SW1 Relations")
	topology.get_node("SW6").get_interface("e0/1").connect_to(topology.get_node("SW3").get_interface("e1/0"))
	topology.get_node("SW6").get_interface("e1/2").connect_to(topology.get_node("SW3").get_interface("e1/1"))
	topology.get_node("SW6").get_interface("e0/0").connect_to(topology.get_node("SW4").get_interface("e0/3"))
	topology.get_node("SW6").get_interface("e1/1").connect_to(topology.get_node("SW4").get_interface("e2/0"))
	topology.get_node("SW6").get_interface("e5/3").connect_to(topology.exit_interface_oob)
	topology.get_node("SW6").get_interface("port 1").connect_to(topology.get_node("SW4").get_interface("port 1"))
	topology.get_node("SW6").get_interface("port 2").connect_to(topology.get_node("SW3").get_interface("port 1"))
