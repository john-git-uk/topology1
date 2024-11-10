from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def SW6_Structures(topology: Topology):
	LOGGER.debug("Loading SW6 Structures")

	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return
		
	machine_data=get_machine_data("viosl2-adventerprisek9-m.ssa.high_iron_20200929")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_SW6_i1=Interface(
		name="0/0",
		interface_type="ethernet",
		channel_group=2
	)
	node_SW6_i2=Interface(
		name="0/1",
		interface_type="ethernet",
		channel_group=1
	)
	node_SW6_i3=Interface(
		name="0/2",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("management")]
	)
	node_SW6_i4=Interface(
		name="0/3",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("internal-services")]
	)
	node_SW6_i5=Interface(
		name="1/0",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest-services")]
	)
	node_SW6_i6=Interface(
		name="1/1",
		interface_type="ethernet",
		channel_group=2
	)
	node_SW6_i7=Interface(
		name="1/2",
		interface_type="ethernet",
		channel_group=1
	)
	node_SW6_i8=Interface(
		name="1/3",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest-services")]
	)
	node_SW6_i9=Interface(
		name="5/3",
		interface_type="ethernet",
		description="out of band",
		ipv4_address="192.168.250.56",
		ipv4_cidr=24
	)
	node_SW6_i10=Interface(
		name="30",
		interface_type="vlan",
		description="",
		ipv4_address="10.133.30.6",
		ipv4_cidr=25
	)
	node_SW6_i11=Interface(
		name="1",
		interface_type="port-channel",
		interfaces=[node_SW6_i2, node_SW6_i7],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		]
	)
	node_SW6_i12=Interface(
		name="2",
		interface_type="port-channel",
		interfaces=[node_SW6_i1, node_SW6_i6],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		]
	)
	node_SW6_i13=Interface(
		name="2/0",
		interface_type="ethernet",
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		]
	)
	node_SW6 = Node(
		hostname="SW6",
		local_user=GLOBALS.sw6_username,
		local_password=GLOBALS.sw6_password,
		machine_data=machine_data,
		oob_interface=node_SW6_i9,
		identity_interface=node_SW6_i10
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
	node_SW6.add_interface(node_SW6_i13)
	topology.add_node(node_SW6)
	access_segment.nodes.append(node_SW6)
	node_SW6.access_segment = access_segment
	
def SW6_relations(topology: Topology):
	LOGGER.debug("Loading SW1 Relations")
	topology.get_node("SW6").get_interface("ethernet","0/1").connect_to(topology.get_node("SW3").get_interface("ethernet","1/0"))
	topology.get_node("SW6").get_interface("ethernet","1/2").connect_to(topology.get_node("SW3").get_interface("ethernet","1/1"))
	topology.get_node("SW6").get_interface("ethernet","0/0").connect_to(topology.get_node("SW4").get_interface("ethernet","0/3"))
	topology.get_node("SW6").get_interface("ethernet","1/1").connect_to(topology.get_node("SW4").get_interface("ethernet","2/0"))
	topology.get_node("SW6").get_interface("ethernet","2/0").connect_to(topology.get_node("prox1").get_interface("ethernet","enp2s0"))
	topology.get_node("SW6").get_interface("ethernet","5/3").connect_to(topology.get_exit_interface('exit_oob'))
	topology.get_node("SW6").get_interface("port-channel","1").connect_to(topology.get_node("SW4").get_interface("port-channel","1"))
	topology.get_node("SW6").get_interface("port-channel","2").connect_to(topology.get_node("SW3").get_interface("port-channel","1"))
