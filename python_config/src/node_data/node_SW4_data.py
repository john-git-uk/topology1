from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
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
		name="0/0",
		interface_type="ethernet",
		channel_group=2
	)
	node_SW4_i2=Interface(
		name="0/1",
		interface_type="ethernet",
		channel_group=2
	)
	node_SW4_i3=Interface(
		name="0/2",
		interface_type="ethernet",
		channel_group=2
	)
	node_SW4_i4=Interface(
		name="0/3",
		interface_type="ethernet",
		channel_group=1
	)
	node_SW4_i5=Interface(
		name="2/0",
		interface_type="ethernet",
		channel_group=1
	)
	node_SW4_i6=Interface(
		name="1/0",
		interface_type="ethernet",
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
		name="1/1",
		interface_type="ethernet",
		description="Connected to SW1",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
		]
	)
	node_SW4_i8=Interface(
		name="1/2",
		interface_type="ethernet",
		description="Connected to SW5",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
		]
	)
	node_SW4_i9=Interface(
		name="10",
		interface_type="vlan",
		ipv4_address="10.133.10.125",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW4_i10=Interface(
		name="20",
		interface_type="vlan",
		ipv4_address="10.133.21.253",
		ipv4_cidr=23,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW4_i11=Interface(
		name="30",
		interface_type="vlan",
		ipv4_address="10.133.30.4",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_SW4_i12=Interface(
		name="40",
		interface_type="vlan",
		ipv4_address="10.133.40.125",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW4_i13=Interface(
		name="60",
		interface_type="vlan",
		ipv4_address="10.133.60.253",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW4_i14=Interface(
		name="70",
		interface_type="vlan",
		ipv4_address="10.133.70.253",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW4_i15=Interface(
		name="80",
		interface_type="vlan",
		ipv4_address="10.133.80.253",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW4_i16=Interface(
		name="1/3",
		interface_type="ethernet",
		description="Connected to R2",
		ipv4_address="10.133.2.67",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_SW4_i17=Interface(
		name="2/1",
		interface_type="ethernet",
		description="Connected to R1",
		ipv4_address="10.133.2.73",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_SW4_i18=Interface(
		name="5/3",
		interface_type="ethernet",
		description="out of band",
		ipv4_address="192.168.250.54",
		ipv4_cidr=24,
		ospf_participant=False,
		ospf_passive=True,
	)
	node_SW4_i19=Interface(
		name="0",
		interface_type="loopback",
		ipv4_address="10.133.2.14",
		ipv4_cidr=32,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_SW4_i20=Interface(
		name="1",
		interface_type="port-channel",
		interfaces=[node_SW4_i4, node_SW4_i5],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		],
		ospf_participant=False,
	)
	node_SW4_i21=Interface(
		name="2",
		interface_type="port-channel",
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
		],
		ospf_participant=False,
	)
	node_SW4=Node(
		hostname="SW4",
		local_user=GLOBALS.sw4_username,
		local_password=GLOBALS.sw4_password,
		machine_data=machine_data,
		oob_interface=node_SW4_i18,
		identity_interface=node_SW4_i19,
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
	node_SW4.access_segment=access_segment
def SW4_relations(topology: Topology):
	LOGGER.debug("Loading SW1 Relations")
	topology.get_node("SW4").get_interface("ethernet","0/0").connect_to(topology.get_node("SW3").get_interface("ethernet","0/0"))
	topology.get_node("SW4").get_interface("ethernet","0/1").connect_to(topology.get_node("SW3").get_interface("ethernet","0/1"))
	topology.get_node("SW4").get_interface("ethernet","0/2").connect_to(topology.get_node("SW3").get_interface("ethernet","0/2"))
	topology.get_node("SW4").get_interface("ethernet","0/3").connect_to(topology.get_node("SW6").get_interface("ethernet","0/0"))
	topology.get_node("SW4").get_interface("ethernet","2/0").connect_to(topology.get_node("SW6").get_interface("ethernet","1/1"))
	topology.get_node("SW4").get_interface("ethernet","1/0").connect_to(topology.get_node("SW2").get_interface("ethernet","0/0"))
	topology.get_node("SW4").get_interface("ethernet","1/1").connect_to(topology.get_node("SW1").get_interface("ethernet","1/0"))
	topology.get_node("SW4").get_interface("ethernet","1/2").connect_to(topology.get_node("SW5").get_interface("ethernet","0/1"))
	topology.get_node("SW4").get_interface("ethernet","1/3").connect_to(topology.get_node("R2").get_interface("ethernet","0/0"))
	topology.get_node("SW4").get_interface("ethernet","2/1").connect_to(topology.get_node("R1").get_interface("gigabit ethernet","3"))
	topology.get_node("SW4").get_interface("ethernet","5/3").connect_to(topology.get_exit_interface('exit_oob'))
	topology.get_node("SW4").get_interface("port-channel","1").connect_to(topology.get_node("SW6").get_interface("port-channel","2"))
	topology.get_node("SW4").get_interface("port-channel","2").connect_to(topology.get_node("SW3").get_interface("port-channel","2"))
