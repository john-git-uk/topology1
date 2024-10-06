from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
LOGGER = logging.getLogger('my_logger')
def SW4_Structures(topology: Topology):
	LOGGER.debug("Loading SW4 Structures")

	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	machine_data=get_machine_data("viosl2-adventerprisek9-m.ssa.high_iron_20200929")
	if(machine_data is None):
		raise ValueError("Machine data not found")

	node_SW4_i1=Interface(
		name="e0/0",
		channel_group=2
	)
	node_SW4_i2=Interface(
		name="e0/1",
		channel_group=2
	)
	node_SW4_i3=Interface(
		name="e0/2",
		channel_group=2
	)
	node_SW4_i4=Interface(
		name="e0/3",
		channel_group=1
	)
	node_SW4_i5=Interface(
		name="e2/0",
		channel_group=1
	)
	node_SW4_i6=Interface(
		name="e1/0",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
			access_segment.get_vlan("accounting")
		]
	)
	node_SW4_i7=Interface(
		name="e1/1",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
		]
	)
	node_SW4_i8=Interface(
		name="e1/2",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
		]
	)
	node_SW4_i9=Interface(
		name="vlan 10",
		ipv4_address="10.133.10.125",
		ipv4_cidr=25
	)
	node_SW4_i10=Interface(
		name="vlan 20",
		ipv4_address="10.133.21.253",
		ipv4_cidr=23
	)
	node_SW4_i11=Interface(
		name="vlan 30",
		ipv4_address="10.133.30.4",
		ipv4_cidr=25
	)
	node_SW4_i12=Interface(
		name="vlan 40",
		ipv4_address="10.133.40.125",
		ipv4_cidr=25
	)
	node_SW4_i13=Interface(
		name="vlan 60",
		ipv4_address="10.133.60.253",
		ipv4_cidr=24
	)
	node_SW4_i14=Interface(
		name="vlan 70",
		ipv4_address="10.133.70.253",
		ipv4_cidr=24
	)
	node_SW4_i15=Interface(
		name="vlan 80",
		ipv4_address="10.133.80.253",
		ipv4_cidr=24
	)
	node_SW4_i16=Interface(
		name="e1/3",
		ipv4_address="10.133.2.67",
		ipv4_cidr=31
	)
	node_SW4_i17=Interface(
		name="e2/1",
		ipv4_address="10.133.2.73",
		ipv4_cidr=31
	)
	node_SW4_i18=Interface(
		name="e5/3",
		description="out of band",
		ipv4_address="192.168.250.54",
		ipv4_cidr=24
	)
	node_SW4_i19=Interface(
		name="loop 0",
		ipv4_address="10.133.2.14",
		ipv4_cidr=32
	)
	node_SW4_i20=Interface(
		name="port 1",
		interfaces=[node_SW4_i4, node_SW4_i5],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		]
	)
	node_SW4_i21=Interface(
		name="port 2",
		interfaces=[node_SW4_i1, node_SW4_i2, node_SW4_i3],
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
			#access_segment.get_vlan("voice"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
			access_segment.get_vlan("accounting")
		]
	)
	node_SW4=Node(
		hostname="SW4",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_SW4_i18
	)
	node_SW4.add_interface(node_SW4_i1)
	node_SW4.add_interface(node_SW4_i2)
	node_SW4.add_interface(node_SW4_i3)
	node_SW4.add_interface(node_SW4_i4)
	node_SW4.add_interface(node_SW4_i5)
	node_SW4.add_interface(node_SW4_i6)
	node_SW4.add_interface(node_SW4_i7)
	node_SW4.add_interface(node_SW4_i8)
	node_SW4.add_interface(node_SW4_i9)
	node_SW4.add_interface(node_SW4_i10)
	node_SW4.add_interface(node_SW4_i11)
	node_SW4.add_interface(node_SW4_i12)
	node_SW4.add_interface(node_SW4_i13)
	node_SW4.add_interface(node_SW4_i14)
	node_SW4.add_interface(node_SW4_i15)
	node_SW4.add_interface(node_SW4_i16)
	node_SW4.add_interface(node_SW4_i17)
	node_SW4.add_interface(node_SW4_i18)
	node_SW4.add_interface(node_SW4_i19)
	node_SW4.add_interface(node_SW4_i20)
	node_SW4.add_interface(node_SW4_i21)

	topology.add_node(node_SW4)
	access_segment.nodes.append(node_SW4)
	access_segment.fhrp.append(node_SW4)
def SW4_relations(topology: Topology):
	LOGGER.debug("Loading SW1 Relations")
	topology.get_node("SW4").get_interface("e0/0").connect_to(topology.get_node("SW3").get_interface("e0/0"))
	topology.get_node("SW4").get_interface("e0/1").connect_to(topology.get_node("SW3").get_interface("e0/1"))
	topology.get_node("SW4").get_interface("e0/2").connect_to(topology.get_node("SW3").get_interface("e0/2"))
	topology.get_node("SW4").get_interface("e0/3").connect_to(topology.get_node("SW6").get_interface("e0/0"))
	topology.get_node("SW4").get_interface("e2/0").connect_to(topology.get_node("SW6").get_interface("e1/1"))
	topology.get_node("SW4").get_interface("e1/0").connect_to(topology.get_node("SW2").get_interface("e0/0"))
	topology.get_node("SW4").get_interface("e1/1").connect_to(topology.get_node("SW1").get_interface("e1/0"))
	topology.get_node("SW4").get_interface("e1/2").connect_to(topology.get_node("SW5").get_interface("e0/1"))
	topology.get_node("SW4").get_interface("e1/3").connect_to(topology.get_node("R2").get_interface("e0/0"))
	topology.get_node("SW4").get_interface("e2/1").connect_to(topology.get_node("R1").get_interface("g3"))
	topology.get_node("SW4").get_interface("e5/3").connect_to(topology.exit_interface_oob)
	topology.get_node("SW4").get_interface("port 1").connect_to(topology.get_node("SW6").get_interface("port 2"))
	topology.get_node("SW4").get_interface("port 2").connect_to(topology.get_node("SW3").get_interface("port 2"))
