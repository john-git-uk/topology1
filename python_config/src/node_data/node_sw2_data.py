from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def sw2_Structures(topology: Topology):
	LOGGER.debug("Loading sw1 Structures")

	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return
		
	machine_data=get_machine_data("Cisco IOU L2 17.12.1")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_sw2_i1=Interface(
		name ="0/0",
		interface_type = 'ethernet',
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
	node_sw2_i2=Interface(
		name ="0/1",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("sales")],
		ospf_participant=False,
	)
	node_sw2_i3=Interface(
		name ="0/2",
		interface_type = 'ethernet',
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
			#access_segment.get_vlan("voice")
			access_segment.get_vlan("accounting")
		],
		ospf_participant=False,
	)
	node_sw2_i4=Interface(
		name ="0/3",
		interface_type = 'ethernet',
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor"),
			#access_segment.get_vlan("voice")
			access_segment.get_vlan("accounting")
		],
		ospf_participant=False,
	)
	node_sw2_i5=Interface(
		name ="1/0",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("sales")],
		ospf_participant=False,
	)
	node_sw2_i6=Interface(
		name ="1/1",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("supervisor")],
		ospf_participant=False,
	)
	node_sw2_i7=Interface(
		name ="1/2",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("sales")],
		ospf_participant=False,
	)
	node_sw2_i8=Interface(
		name ="1/3",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("guest")],
		ospf_participant=False,
	)
	node_sw2_i9=Interface(
		name ="2/0",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("guest")],
		ospf_participant=False,
	)
	node_sw2_i10=Interface(
		name ="2/1",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("guest")],
		ospf_participant=False,
	)
	node_sw2_i11=Interface(
		name ="2/2",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("accounting")],
		ospf_participant=False,
	)
	node_sw2_i12=Interface(
		name ="2/3",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("guest")],
		ospf_participant=False,
	)
	node_sw2_i13=Interface(
		name ="3/3",
		interface_type = 'ethernet',
		description="out of band",
		ipv4_address="192.168.250.52",
		ipv4_cidr=24,
		ospf_participant=False,
	)
	node_sw2_i14=Interface(
		name ="30",
		interface_type="vlan",
		description="",
		ipv4_address="10.133.30.2",
		ipv4_cidr=25,
	)
	node_sw2=Node(
		hostname ="sw2",
		local_user=GLOBALS.sw2_username,
		local_password=GLOBALS.sw2_password,
		machine_data=machine_data,
		oob_interface=node_sw2_i13,
		identity_interface=node_sw2_i14,
		additional_config=sw2_additional_config
	)
	node_sw2.add_interface(node_sw2_i1)
	node_sw2.add_interface(node_sw2_i2)
	node_sw2.add_interface(node_sw2_i3)
	node_sw2.add_interface(node_sw2_i4)
	node_sw2.add_interface(node_sw2_i5)
	node_sw2.add_interface(node_sw2_i6)
	node_sw2.add_interface(node_sw2_i7)
	node_sw2.add_interface(node_sw2_i8)
	node_sw2.add_interface(node_sw2_i9)
	node_sw2.add_interface(node_sw2_i10)
	node_sw2.add_interface(node_sw2_i11)
	node_sw2.add_interface(node_sw2_i12)
	node_sw2.add_interface(node_sw2_i13)
	node_sw2.add_interface(node_sw2_i14)

	topology.add_node(node_sw2)
	access_segment.nodes.append(node_sw2)
	node_sw2.access_segment=access_segment

def sw2_relations(topology: Topology):
	sw1_node = topology.get_node("sw1")
	if sw1_node is None:
		LOGGER.error("sw1 node not found")
		return
	sw2_node = topology.get_node("sw2")
	if sw2_node is None:
		LOGGER.error("sw2 node not found")
		return
	sw3_node = topology.get_node("sw3")
	if sw3_node is None:
		LOGGER.error("sw3 node not found")
		return
	sw4_node = topology.get_node("sw4")
	if sw4_node is None:
		LOGGER.error("sw4 node not found")
		return
	######################################################################
	LOGGER.debug("Loading sw2 Relations")
	sw2_node.get_interface("ethernet","0/0").connect_to(sw4_node.get_interface("ethernet","1/0"))
	sw2_node.get_interface("ethernet","0/2").connect_to(sw1_node.get_interface("ethernet","0/2"))
	sw2_node.get_interface("ethernet","0/3").connect_to(sw3_node.get_interface("ethernet","3/0"))
	sw2_node.get_interface("ethernet","3/3").connect_to(topology.get_exit_interface('exit_oob'))

def sw2_additional_config(node: Node):
	if node.hostname != 'sw2':
		LOGGER.error('{node.hostname} additional config was passed another node.')
		return
	LOGGER.debug(f'{node.hostname} has no additional config at the moment.')
	return