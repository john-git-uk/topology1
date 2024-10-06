from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
LOGGER = logging.getLogger('my_logger')
def SW7_Structures(topology: Topology):
	LOGGER.debug("Loading SW7 Structures")

	for segs in topology.access_segments:
		if(segs.name == "outreach"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	machine_data=get_machine_data("viosl2-adventerprisek9-m.ssa.high_iron_20200929")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_SW7_i1=Interface(
		name="e0/0",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
		]
	)
	node_SW7_i2=Interface(
		name="e0/1",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW7_i3=Interface(
		name="e0/2",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW7_i4=Interface(
		name="e0/3",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW7_i5=Interface(
		name="e1/0",
		trunk=False,
		vlans=[access_segment.get_vlan("supervisor")]
	)
	node_SW7_i6=Interface(
		name="e1/1",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW7_i7=Interface(
		name="e1/2",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW7_i8=Interface(
		name="e1/3",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW7_i9=Interface(
		name="e2/0",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW7_i10=Interface(
		name="e2/1",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW7_i11=Interface(
		name="e3/3",
		description="out of band",
		ipv4_address="192.168.250.57",
		ipv4_cidr=24
	)
	node_SW7_i12=Interface(
		name="vlan 30",
		description="",
		ipv4_address="10.133.30.137",
		ipv4_cidr=25
	)
	node_SW7_i13=Interface(
		name="loop 0",
		description="",
		ipv4_address="10.133.2.17",
		ipv4_cidr=32
	)
	node_SW7 = Node(
		hostname="SW7",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_SW7_i11
	)
	node_SW7.add_interface(node_SW7_i1)
	node_SW7.add_interface(node_SW7_i2)
	node_SW7.add_interface(node_SW7_i3)
	node_SW7.add_interface(node_SW7_i4)
	node_SW7.add_interface(node_SW7_i5)
	node_SW7.add_interface(node_SW7_i6)
	node_SW7.add_interface(node_SW7_i7)
	node_SW7.add_interface(node_SW7_i8)
	node_SW7.add_interface(node_SW7_i9)
	node_SW7.add_interface(node_SW7_i10)
	node_SW7.add_interface(node_SW7_i11)
	node_SW7.add_interface(node_SW7_i12)
	node_SW7.add_interface(node_SW7_i13)
	topology.add_node(node_SW7)
	access_segment.nodes.append(node_SW7)
def SW7_relations(topology: Topology):
	LOGGER.debug("Loading SW1 Relations")
	topology.get_node("SW7").get_interface("e0/0").connect_to(topology.get_node("R3").get_interface("e0/1"))
	topology.get_node("SW7").get_interface("e3/3").connect_to(topology.exit_interface_oob)
