from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def SW5_Structures(topology: Topology):
	LOGGER.debug("Loading SW5 Structures")

	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	machine_data=get_machine_data("Cisco IOU L2 17.12.1")
	if(machine_data is None):
		raise ValueError("Machine data not found")

	node_SW5_i1=Interface(
		name="0/0",
		interface_type="ethernet",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
			#access_segment.get_vlan("voice"),
		]
	)
	node_SW5_i2=Interface(
		name="0/1",
		interface_type="ethernet",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
			#access_segment.get_vlan("voice"),
		]
	)
	node_SW5_i3=Interface(
		name="0/2",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW5_i4=Interface(
		name="0/3",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")]
	)
	node_SW5_i5=Interface(
		name="1/0",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("supervisor")]
	)
	node_SW5_i6=Interface(
		name="1/1",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW5_i7=Interface(
		name="1/2",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW5_i8=Interface(
		name="1/3",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW5_i9=Interface(
		name="2/0",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")]
	)
	node_SW5_i10=Interface(
		name="3/3",
		interface_type="ethernet",
		description="out of band",
		ipv4_address="192.168.250.55",
		ipv4_cidr=24
	)
	node_SW5_i11=Interface(
		name="30",
		interface_type="vlan",
		description="",
		ipv4_address="10.133.30.5",
		ipv4_cidr=25
	)

	node_SW5=Node(
		hostname="SW5",
		local_user=GLOBALS.sw5_username,
		local_password=GLOBALS.sw5_password,
		machine_data=machine_data,
		oob_interface=node_SW5_i10,
		identity_interface=node_SW5_i11
	)
	node_SW5.add_interface(node_SW5_i1)
	node_SW5.add_interface(node_SW5_i2)
	node_SW5.add_interface(node_SW5_i3)
	node_SW5.add_interface(node_SW5_i4)
	node_SW5.add_interface(node_SW5_i5)
	node_SW5.add_interface(node_SW5_i6)
	node_SW5.add_interface(node_SW5_i7)
	node_SW5.add_interface(node_SW5_i8)
	node_SW5.add_interface(node_SW5_i9)
	node_SW5.add_interface(node_SW5_i10)
	node_SW5.add_interface(node_SW5_i11)
	topology.add_node(node_SW5)
	access_segment.nodes.append(node_SW5)
	node_SW5.access_segment=access_segment
	
def SW5_relations(topology: Topology):
	LOGGER.debug("Loading SW5 Relations")
	topology.get_node("SW5").get_interface("ethernet","0/0").connect_to(topology.get_node("SW3").get_interface("ethernet","0/3"))
	topology.get_node("SW5").get_interface("ethernet","0/1").connect_to(topology.get_node("SW4").get_interface("ethernet","1/2"))
	topology.get_node("SW5").get_interface("ethernet","3/3").connect_to(topology.get_exit_interface('exit_oob'))
