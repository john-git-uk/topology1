from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def sw6_Structures(topology: Topology):
	LOGGER.debug("Loading sw6 Structures")

	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return
		
	machine_data=get_machine_data("Cisco IOU L2 17.12.1")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_sw6_i1=Interface(
		name ="0/0",
		interface_type = 'ethernet',
		channel_group=2
	)
	node_sw6_i2=Interface(
		name ="0/1",
		interface_type = 'ethernet',
		channel_group=1
	)
	node_sw6_i3=Interface(
		name ="0/2",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("management")]
	)
	node_sw6_i4=Interface(
		name ="0/3",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("internal-services")]
	)
	node_sw6_i5=Interface(
		name ="1/0",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("guest-services")]
	)
	node_sw6_i6=Interface(
		name ="1/1",
		interface_type = 'ethernet',
		channel_group=2
	)
	node_sw6_i7=Interface(
		name ="1/2",
		interface_type = 'ethernet',
		channel_group=1
	)
	node_sw6_i8=Interface(
		name ="1/3",
		interface_type = 'ethernet',
		trunk=False,
		vlans=[access_segment.get_vlan("guest-services")]
	)
	node_sw6_i9=Interface(
		name ="3/3",
		interface_type = 'ethernet',
		description="out of band",
		ipv4_address="192.168.250.56",
		ipv4_cidr=24
	)
	node_sw6_i10=Interface(
		name ="30",
		interface_type="vlan",
		description="",
		ipv4_address="10.133.30.6",
		ipv4_cidr=25
	)
	node_sw6_i11=Interface(
		name ="1",
		interface_type="port-channel",
		interfaces=[node_sw6_i2, node_sw6_i7],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		]
	)
	node_sw6_i12=Interface(
		name ="2",
		interface_type="port-channel",
		interfaces=[node_sw6_i1, node_sw6_i6],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		]
	)
	node_sw6_i13=Interface(
		name ="2/0",
		interface_type = 'ethernet',
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		]
	)
	node_sw6 = Node(
		hostname ="sw6",
		local_user=GLOBALS.sw6_username,
		local_password=GLOBALS.sw6_password,
		machine_data=machine_data,
		oob_interface=node_sw6_i9,
		identity_interface=node_sw6_i10,
		additional_config=sw6_additional_config
	)
	node_sw6.add_interface(node_sw6_i1)
	node_sw6.add_interface(node_sw6_i2)
	node_sw6.add_interface(node_sw6_i3)
	node_sw6.add_interface(node_sw6_i4)
	node_sw6.add_interface(node_sw6_i5)
	node_sw6.add_interface(node_sw6_i6)
	node_sw6.add_interface(node_sw6_i7)
	node_sw6.add_interface(node_sw6_i8)
	node_sw6.add_interface(node_sw6_i9)
	node_sw6.add_interface(node_sw6_i10)
	node_sw6.add_interface(node_sw6_i11)
	node_sw6.add_interface(node_sw6_i12)
	node_sw6.add_interface(node_sw6_i13)
	topology.add_node(node_sw6)
	access_segment.nodes.append(node_sw6)
	node_sw6.access_segment = access_segment
	
def sw6_relations(topology: Topology):
	r1_node = topology.get_node("r1")
	if r1_node is None:
		LOGGER.error("r1 node not found")
		return
	r2_node = topology.get_node("r2")
	if r2_node is None:
		LOGGER.error("r2 node not found")
		return
	r3_node = topology.get_node("r3")
	if r3_node is None:
		LOGGER.error("r3 node not found")
		return
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
	sw5_node = topology.get_node("sw5")
	if sw5_node is None:
		LOGGER.error("sw5 node not found")
		return
	sw6_node = topology.get_node("sw6")
	if sw6_node is None:
		LOGGER.error("sw6 node not found")
		return
	sw7_node = topology.get_node("sw7")
	if sw7_node is None:
		LOGGER.error("sw7 node not found")
		return
	prox1_node = topology.get_node("prox1")
	if prox1_node is None:
		LOGGER.error("prox1 node not found")
		return
	######################################################################
	LOGGER.debug("Loading sw1 Relations")
	sw6_node.get_interface("ethernet","0/1").connect_to(sw3_node.get_interface("ethernet","1/0"))
	sw6_node.get_interface("ethernet","1/2").connect_to(sw3_node.get_interface("ethernet","1/1"))
	sw6_node.get_interface("ethernet","0/0").connect_to(sw4_node.get_interface("ethernet","0/3"))
	sw6_node.get_interface("ethernet","1/1").connect_to(sw4_node.get_interface("ethernet","2/0"))
	sw6_node.get_interface("ethernet","2/0").connect_to(prox1_node.get_interface("ethernet","enp2s0"))
	sw6_node.get_interface("ethernet","3/3").connect_to(topology.get_exit_interface('exit_oob'))
	sw6_node.get_interface("port-channel","1").connect_to(sw4_node.get_interface("port-channel","1"))
	sw6_node.get_interface("port-channel","2").connect_to(sw3_node.get_interface("port-channel","1"))

def sw6_additional_config(node: Node):
	if node.hostname != 'sw6':
		LOGGER.error('{node.hostname} additional config was passed another node.')
		return
	LOGGER.debug(f'{node.hostname} has no additional config at the moment.')
	return