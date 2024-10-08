from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
LOGGER = logging.getLogger('my_logger')
def SW3_Structures(topology: Topology):
	LOGGER.debug("Loading SW3 Structures")

	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return
	machine_data=get_machine_data("viosl2-adventerprisek9-m.ssa.high_iron_20200929")

	if(machine_data is None):
		raise ValueError("Machine data not found")
	node_SW3_i1=Interface(
		name="e0/0",
		channel_group=2
	)
	node_SW3_i2=Interface(
		name="e0/1",
		channel_group=2
	)
	node_SW3_i3=Interface(
		name="e0/2",
		channel_group=2
	)
	node_SW3_i4=Interface(
		name="e1/0",
		channel_group=1
	)
	node_SW3_i5=Interface(
		name="e1/1",
		channel_group=1
	)
	node_SW3_i6=Interface(
		name="e0/3",
		description="Connected to SW5",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor")#,
			#access_segment.get_vlan("voice")
		]
	)
	node_SW3_i7=Interface(
		name="e2/0",
		description="Connected to SW1",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
		]
	)
	node_SW3_i8=Interface(
		name="e3/0",
		description="Connected to SW2",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
			#access_segment.get_vlan("voice"),
			access_segment.get_vlan("accounting")
		]
	)
	node_SW3_i9=Interface(
		name="vlan 10",
		ipv4_address="10.133.10.124",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i10=Interface(
		name="vlan 20",
		ipv4_address="10.133.21.252",
		ipv4_cidr=23,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i11=Interface(
		name="vlan 30",
		ipv4_address="10.133.30.3",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_SW3_i12=Interface(
		name="vlan 40",
		ipv4_address="10.133.40.124",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i13=Interface(
		name="vlan 60",
		ipv4_address="10.133.60.252",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i14=Interface(
		name="vlan 70",
		ipv4_address="10.133.70.252",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i15=Interface(
		name="vlan 80",
		ipv4_address="10.133.80.252",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i16=Interface(
		name="e4/0",
		description="Connected to R1",
		ipv4_address="10.133.2.65",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_SW3_i17=Interface(
		name="e1/2",
		description="Connected to R2",
		ipv4_address="10.133.2.75",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_SW3_i18=Interface(
		name="e5/3",
		description="out of band",
		ipv4_address="192.168.250.53",
		ipv4_cidr=24,
		ospf_participant=False,
		ospf_passive=True,
	)
	node_SW3_i19=Interface(
		name="loop 0",
		ipv4_address="10.133.2.13",
		ipv4_cidr=32,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i20=Interface(
		name="port 1",
		interfaces=[node_SW3_i4, node_SW3_i5],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		],
	)
	node_SW3_i21=Interface(
		name="port 2",
		interfaces=[node_SW3_i1, node_SW3_i2, node_SW3_i3],
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
		],
	)
	node_SW3=Node(
		hostname="SW3",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_SW3_i18
	)
	node_SW3.add_interface(node_SW3_i1)
	node_SW3.add_interface(node_SW3_i2)
	node_SW3.add_interface(node_SW3_i3)
	node_SW3.add_interface(node_SW3_i4)
	node_SW3.add_interface(node_SW3_i5)
	node_SW3.add_interface(node_SW3_i6)
	node_SW3.add_interface(node_SW3_i7)
	node_SW3.add_interface(node_SW3_i8)
	node_SW3.add_interface(node_SW3_i9)
	node_SW3.add_interface(node_SW3_i10)
	node_SW3.add_interface(node_SW3_i11)
	node_SW3.add_interface(node_SW3_i12)
	node_SW3.add_interface(node_SW3_i13)
	node_SW3.add_interface(node_SW3_i14)
	node_SW3.add_interface(node_SW3_i15)
	node_SW3.add_interface(node_SW3_i16)
	node_SW3.add_interface(node_SW3_i17)
	node_SW3.add_interface(node_SW3_i18)
	node_SW3.add_interface(node_SW3_i19)
	node_SW3.add_interface(node_SW3_i20)
	node_SW3.add_interface(node_SW3_i21)
	topology.add_node(node_SW3)
	access_segment.nodes.append(node_SW3)
	access_segment.fhrp.append(node_SW3)
def SW3_relations(topology: Topology):
	LOGGER.debug("Loading SW1 Relations")
	topology.get_node("SW3").get_interface("e0/0").connect_to(topology.get_node("SW4").get_interface("e0/0"))
	topology.get_node("SW3").get_interface("e0/1").connect_to(topology.get_node("SW4").get_interface("e0/1"))
	topology.get_node("SW3").get_interface("e0/2").connect_to(topology.get_node("SW4").get_interface("e0/2"))
	topology.get_node("SW3").get_interface("e0/3").connect_to(topology.get_node("SW5").get_interface("e0/0"))
	topology.get_node("SW3").get_interface("e1/0").connect_to(topology.get_node("SW6").get_interface("e0/1"))
	topology.get_node("SW3").get_interface("e1/1").connect_to(topology.get_node("SW6").get_interface("e1/2"))
	topology.get_node("SW3").get_interface("e1/2").connect_to(topology.get_node("R2").get_interface("e0/2"))
	topology.get_node("SW3").get_interface("e2/0").connect_to(topology.get_node("SW1").get_interface("e0/3"))
	topology.get_node("SW3").get_interface("e3/0").connect_to(topology.get_node("SW2").get_interface("e0/3"))
	topology.get_node("SW3").get_interface("e4/0").connect_to(topology.get_node("R1").get_interface("g1"))
	topology.get_node("SW3").get_interface("e5/3").connect_to(topology.exit_interface_oob)
	topology.get_node("SW3").get_interface("port 1").connect_to(topology.get_node("SW6").get_interface("port 1"))
	topology.get_node("SW3").get_interface("port 2").connect_to(topology.get_node("SW4").get_interface("port 2"))
