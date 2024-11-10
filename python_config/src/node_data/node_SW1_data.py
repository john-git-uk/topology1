from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def SW1_Structures(topology: Topology):
	LOGGER.debug("Loading SW1 Structures")
	
	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	machine_data=get_machine_data("viosl2-adventerprisek9-m.ssa.high_iron_20200929")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_SW1_i1=Interface(
		name="0/0",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")],
		ospf_participant=False,
	)
	node_SW1_i2=Interface(
		name="0/1",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")],
		ospf_participant=False,
	)
	node_SW1_i3=Interface(
		name="0/2",
		interface_type="ethernet",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor")#,
			#access_segment.get_vlan("voice")
		],
		ospf_participant=False,
	)
	node_SW1_i4=Interface(
		name="0/3",
		interface_type="ethernet",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor")#,
			#access_segment.get_vlan("voice")
		],
		ospf_participant=False,
	)
	node_SW1_i5=Interface(
		name="1/0",
		interface_type="ethernet",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor")#,
			#access_segment.get_vlan("voice")
		],
		ospf_participant=False,
	)
	node_SW1_i6=Interface(
		name="1/1",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")],
		ospf_participant=False,
	)
	node_SW1_i7=Interface(
		name="1/2",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")],
		ospf_participant=False,
	)
	node_SW1_i8=Interface(
		name="1/3",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("sales")],
		ospf_participant=False,
	)
	node_SW1_i9=Interface(
		name="2/0",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")],
		ospf_participant=False,
	)
	node_SW1_i10=Interface(
		name="2/1",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")],
		ospf_participant=False,
	)
	node_SW1_i11=Interface(
		name="2/2",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")],
		ospf_participant=False,
	)
	node_SW1_i12=Interface(
		name="2/3",
		interface_type="ethernet",
		trunk=False,
		vlans=[access_segment.get_vlan("guest")],
		ospf_participant=False,
	)
	node_SW1_i13=Interface(
		name="3/0",
		interface_type="ethernet",
		trunk=False,
		ospf_participant=False,
	)
	node_SW1_i14=Interface(
		name="30",
		interface_type="vlan",
		ipv4_address="10.133.30.1",
		ipv4_cidr=25,
		ospf_participant=False,
	)
	node_SW1_i15=Interface(
		name="3/3",
		interface_type="ethernet",
		description="out of band",
		ipv4_address="192.168.250.51",
		ipv4_cidr=24,
		ospf_participant=False,
	)
	node_SW1=Node(
		hostname="SW1",
		local_user=GLOBALS.sw1_username,
		local_password=GLOBALS.sw1_password,
		machine_data=machine_data,
		oob_interface=node_SW1_i15,
		identity_interface=node_SW1_i14
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
	node_SW1.access_segment=access_segment
	
def SW1_relations(topology: Topology):
	LOGGER.debug("Loading SW1 Relations")
	topology.get_node("SW1").get_interface("ethernet","0/2").connect_to(topology.get_node("SW2").get_interface("ethernet","0/2"))
	topology.get_node("SW1").get_interface("ethernet","0/3").connect_to(topology.get_node("SW3").get_interface("ethernet","2/0"))
	topology.get_node("SW1").get_interface("ethernet","1/0").connect_to(topology.get_node("SW4").get_interface("ethernet","1/1"))
	topology.get_node("SW1").get_interface("ethernet","3/3").connect_to(topology.get_exit_interface('exit_oob'))
