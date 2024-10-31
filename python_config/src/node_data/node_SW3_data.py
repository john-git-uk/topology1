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
		name="0/0",
		interface_type="ethernet",
		channel_group=2
	)
	node_SW3_i2=Interface(
		name="0/1",
		interface_type="ethernet",
		channel_group=2
	)
	node_SW3_i3=Interface(
		name="0/2",
		interface_type="ethernet",
		channel_group=2
	)
	node_SW3_i4=Interface(
		name="1/0",
		interface_type="ethernet",
		channel_group=1
	)
	node_SW3_i5=Interface(
		name="1/1",
		interface_type="ethernet",
		channel_group=1
	)
	node_SW3_i6=Interface(
		name="0/3",
		interface_type="ethernet",
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
		name="2/0",
		interface_type="ethernet",
		description="Connected to SW1",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
		]
	)
	node_SW3_i8=Interface(
		name="3/0",
		interface_type="ethernet",
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
		name="10",
		interface_type="vlan",
		ipv4_address="10.133.10.124",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i10=Interface(
		name="20",
		interface_type="vlan",
		ipv4_address="10.133.21.252",
		ipv4_cidr=23,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i11=Interface(
		name="30",
		interface_type="vlan",
		ipv4_address="10.133.30.3",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_SW3_i12=Interface(
		name="40",
		interface_type="vlan",
		ipv4_address="10.133.40.124",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i13=Interface(
		name="60",
		interface_type="vlan",
		ipv4_address="10.133.60.252",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i14=Interface(
		name="70",
		interface_type="vlan",
		ipv4_address="10.133.70.252",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i15=Interface(
		name="80",
		interface_type="vlan",
		ipv4_address="10.133.80.252",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i16=Interface(
		name="4/0",
		interface_type="ethernet",
		description="Connected to R1",
		ipv4_address="10.133.2.65",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_SW3_i17=Interface(
		name="1/2",
		interface_type="ethernet",
		description="Connected to R2",
		ipv4_address="10.133.2.75",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_SW3_i18=Interface(
		name="5/3",
		interface_type="ethernet",
		description="out of band",
		ipv4_address="192.168.250.53",
		ipv4_cidr=24,
		ospf_participant=False,
		ospf_passive=True,
	)
	node_SW3_i19=Interface(
		name="0",
		interface_type="loopback",
		ipv4_address="10.133.2.13",
		ipv4_cidr=32,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW3_i20=Interface(
		name="1",
		interface_type="port-channel",
		interfaces=[node_SW3_i4, node_SW3_i5],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		],
	)
	node_SW3_i21=Interface(
		name="2",
		interface_type="port-channel",
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
	topology.get_node("SW3").get_interface("ethernet","0/0").connect_to(topology.get_node("SW4").get_interface("ethernet","0/0"))
	topology.get_node("SW3").get_interface("ethernet","0/1").connect_to(topology.get_node("SW4").get_interface("ethernet","0/1"))
	topology.get_node("SW3").get_interface("ethernet","0/2").connect_to(topology.get_node("SW4").get_interface("ethernet","0/2"))
	topology.get_node("SW3").get_interface("ethernet","0/3").connect_to(topology.get_node("SW5").get_interface("ethernet","0/0"))
	topology.get_node("SW3").get_interface("ethernet","1/0").connect_to(topology.get_node("SW6").get_interface("ethernet","0/1"))
	topology.get_node("SW3").get_interface("ethernet","1/1").connect_to(topology.get_node("SW6").get_interface("ethernet","1/2"))
	topology.get_node("SW3").get_interface("ethernet","1/2").connect_to(topology.get_node("R2").get_interface("ethernet","0/2"))
	topology.get_node("SW3").get_interface("ethernet","2/0").connect_to(topology.get_node("SW1").get_interface("ethernet","0/3"))
	topology.get_node("SW3").get_interface("ethernet","3/0").connect_to(topology.get_node("SW2").get_interface("ethernet","0/3"))
	topology.get_node("SW3").get_interface("ethernet","4/0").connect_to(topology.get_node("R1").get_interface("gigabit ethernet","1"))
	topology.get_node("SW3").get_interface("ethernet","5/3").connect_to(topology.exit_interface_oob)
	topology.get_node("SW3").get_interface("port-channel","1").connect_to(topology.get_node("SW6").get_interface("port-channel","1"))
	topology.get_node("SW3").get_interface("port-channel","2").connect_to(topology.get_node("SW4").get_interface("port-channel","2"))
