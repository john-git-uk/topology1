from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
LOGGER = logging.getLogger('my_logger')
def SW1_Structures(topology: Topology):
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
		
	node_SW1_i1=Interface(
		name="e0/0",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW1_i2=Interface(
		name="e0/1",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW1_i3=Interface(
		name="e0/2",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor")#,
			#access_segment.get_vlan("voice")
		]
	)
	node_SW1_i4=Interface(
		name="e0/3",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor")#,
			#access_segment.get_vlan("voice")
		]
	)
	node_SW1_i5=Interface(
		name="e1/0",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor")#,
			#access_segment.get_vlan("voice")
		]
	)
	node_SW1_i6=Interface(
		name="e1/1",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW1_i7=Interface(
		name="e1/2",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW1_i8=Interface(
		name="e1/3",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW1_i9=Interface(
		name="e2/0",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW1_i10=Interface(
		name="e2/1",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW1_i11=Interface(
		name="e2/2",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW1_i12=Interface(
		name="e2/3",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW1_i13=Interface(
		name="e3/0",
		trunk=False
	)
	node_SW1_i14=Interface(
		name="vlan 30",
		ipv4_address="10.133.30.2",
		ipv4_cidr=25
	)
	node_SW1_i15=Interface(
		name="e3/3",
		description="out of band",
		ipv4_address="192.168.250.51",
		ipv4_cidr=24
	)
	node_SW1_i16=Interface(  # noqa: F841
		name="l0",
		description="",
		ipv4_address="10.133.2.11",
		ipv4_cidr=32
	)
	node_SW1=Node(
		hostname="SW1",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_SW1_i15
	)
	node_SW1.add_interface(node_SW1_i1)
	node_SW1.add_interface(node_SW1_i2)
	node_SW1.add_interface(node_SW1_i3)
	node_SW1.add_interface(node_SW1_i4)
	node_SW1.add_interface(node_SW1_i5)
	node_SW1.add_interface(node_SW1_i6)
	node_SW1.add_interface(node_SW1_i7)
	node_SW1.add_interface(node_SW1_i8)
	node_SW1.add_interface(node_SW1_i9)
	node_SW1.add_interface(node_SW1_i10)
	node_SW1.add_interface(node_SW1_i11)
	node_SW1.add_interface(node_SW1_i12)
	node_SW1.add_interface(node_SW1_i13)
	node_SW1.add_interface(node_SW1_i14)
	node_SW1.add_interface(node_SW1_i15)
	topology.add_node(node_SW1)
	access_segment.nodes.append(node_SW1)
def SW1_relations(topology: Topology):
	LOGGER.debug("Loading SW1 Relations")
	topology.get_node("SW1").get_interface("e0/2").connect_to(topology.get_node("SW2").get_interface("e0/2"))
	topology.get_node("SW1").get_interface("e0/3").connect_to(topology.get_node("SW3").get_interface("e2/0"))
	topology.get_node("SW1").get_interface("e1/0").connect_to(topology.get_node("SW4").get_interface("e1/1"))
	topology.get_node("SW1").get_interface("e3/3").connect_to(topology.exit_interface_oob)
