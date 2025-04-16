from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def sw3_Structures(topology: Topology):
	LOGGER.debug("Loading sw3 Structures")

	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return
	machine_data=get_machine_data("Cisco IOU L2 17.12.1")

	if(machine_data is None):
		raise ValueError("Machine data not found")
	node_sw3_i1=Interface(
		name ="0/0",
		interface_type = 'ethernet',
		channel_group=2
	)
	node_sw3_i2=Interface(
		name ="0/1",
		interface_type = 'ethernet',
		channel_group=2
	)
	node_sw3_i3=Interface(
		name ="0/2",
		interface_type = 'ethernet',
		channel_group=2
	)
	node_sw3_i4=Interface(
		name ="1/0",
		interface_type = 'ethernet',
		channel_group=1
	)
	node_sw3_i5=Interface(
		name ="1/1",
		interface_type = 'ethernet',
		channel_group=1
	)
	node_sw3_i6=Interface(
		name ="0/3",
		interface_type = 'ethernet',
		description="Connected to sw5",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
			access_segment.get_vlan("supervisor")#,
			#access_segment.get_vlan("voice")
		]
	)
	node_sw3_i7=Interface(
		name ="2/0",
		interface_type = 'ethernet',
		description="Connected to sw1",
		trunk=True,
		vlans=[
			access_segment.get_vlan("sales"),
			access_segment.get_vlan("guest"),
			access_segment.get_vlan("management"),
		]
	)
	node_sw3_i8=Interface(
		name ="3/0",
		interface_type = 'ethernet',
		description="Connected to sw2",
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
	node_sw3_i9=Interface(
		name ="10",
		interface_type="vlan",
		ipv4_address="10.133.10.124",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_sw3_i10=Interface(
		name ="20",
		interface_type="vlan",
		ipv4_address="10.133.21.252",
		ipv4_cidr=23,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_sw3_i11=Interface(
		name ="30",
		interface_type="vlan",
		ipv4_address="10.133.30.3",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_sw3_i12=Interface(
		name ="40",
		interface_type="vlan",
		ipv4_address="10.133.40.124",
		ipv4_cidr=25,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_sw3_i13=Interface(
		name ="60",
		interface_type="vlan",
		ipv4_address="10.133.60.252",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_sw3_i14=Interface(
		name ="70",
		interface_type="vlan",
		ipv4_address="10.133.70.252",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_sw3_i15=Interface(
		name ="80",
		interface_type="vlan",
		ipv4_address="10.133.80.252",
		ipv4_cidr=24,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_sw3_i16=Interface(
		name ="1/3",
		interface_type = 'ethernet',
		description="Connected to r1",
		ipv4_address="10.133.2.65",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_sw3_i17=Interface(
		name ="1/2",
		interface_type = 'ethernet',
		description="Connected to r2",
		ipv4_address="10.133.2.75",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
	)
	node_sw3_i18=Interface(
		name ="3/3",
		interface_type = 'ethernet',
		description="out of band",
		ipv4_address="192.168.250.53",
		ipv4_cidr=24,
		ospf_participant=False,
		ospf_passive=True,
	)
	node_sw3_i19=Interface(
		name ="0",
		interface_type="loopback",
		ipv4_address="10.133.2.13",
		ipv4_cidr=32,
		ospf_participant=True,
		ospf_passive=True,
	)
	node_sw3_i20=Interface(
		name ="1",
		interface_type="port-channel",
		interfaces=[node_sw3_i4, node_sw3_i5],
		trunk=True,
		vlans=[
			access_segment.get_vlan("management"),
			access_segment.get_vlan("guest-services"),
			access_segment.get_vlan("internal-services"),
		],
	)
	node_sw3_i21=Interface(
		name ="2",
		interface_type="port-channel",
		interfaces=[node_sw3_i1, node_sw3_i2, node_sw3_i3],
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
	node_sw3=Node(
		hostname ="sw3",
		local_user=GLOBALS.sw3_username,
		local_password=GLOBALS.sw3_password,
		machine_data=machine_data,
		oob_interface=node_sw3_i18,
		identity_interface=node_sw3_i19,
		additional_config=sw3_additional_config
	)
	node_sw3.add_interface(node_sw3_i1)
	node_sw3.add_interface(node_sw3_i2)
	node_sw3.add_interface(node_sw3_i3)
	node_sw3.add_interface(node_sw3_i4)
	node_sw3.add_interface(node_sw3_i5)
	node_sw3.add_interface(node_sw3_i6)
	node_sw3.add_interface(node_sw3_i7)
	node_sw3.add_interface(node_sw3_i8)
	node_sw3.add_interface(node_sw3_i9)
	node_sw3.add_interface(node_sw3_i10)
	node_sw3.add_interface(node_sw3_i11)
	node_sw3.add_interface(node_sw3_i12)
	node_sw3.add_interface(node_sw3_i13)
	node_sw3.add_interface(node_sw3_i14)
	node_sw3.add_interface(node_sw3_i15)
	node_sw3.add_interface(node_sw3_i16)
	node_sw3.add_interface(node_sw3_i17)
	node_sw3.add_interface(node_sw3_i18)
	node_sw3.add_interface(node_sw3_i19)
	node_sw3.add_interface(node_sw3_i20)
	node_sw3.add_interface(node_sw3_i21)
	topology.add_node(node_sw3)
	access_segment.nodes.append(node_sw3)
	access_segment.fhrp.append(node_sw3)
	node_sw3.access_segment=access_segment

def sw3_relations(topology: Topology):
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
	######################################################################
	LOGGER.debug("Loading sw1 Relations")
	sw3_node.get_interface("ethernet","0/0").connect_to(sw4_node.get_interface("ethernet","0/0"))
	sw3_node.get_interface("ethernet","0/1").connect_to(sw4_node.get_interface("ethernet","0/1"))
	sw3_node.get_interface("ethernet","0/2").connect_to(sw4_node.get_interface("ethernet","0/2"))
	sw3_node.get_interface("ethernet","0/3").connect_to(sw5_node.get_interface("ethernet","0/0"))
	sw3_node.get_interface("ethernet","1/0").connect_to(sw6_node.get_interface("ethernet","0/1"))
	sw3_node.get_interface("ethernet","1/1").connect_to(sw6_node.get_interface("ethernet","1/2"))
	sw3_node.get_interface("ethernet","1/2").connect_to(r2_node.get_interface("ethernet","0/2"))
	sw3_node.get_interface("ethernet","2/0").connect_to(sw1_node.get_interface("ethernet","0/3"))
	sw3_node.get_interface("ethernet","3/0").connect_to(sw2_node.get_interface("ethernet","0/3"))
	if r1_node.machine_data.gigabit_naming:
		sw3_node.get_interface("ethernet","1/3").connect_to(r1_node.get_interface("gigabitethernet","1"))
	else:
		sw3_node.get_interface("ethernet","1/3").connect_to(r1_node.get_interface("ethernet","0/0"))
	sw3_node.get_interface("ethernet","3/3").connect_to(topology.get_exit_interface('exit_oob'))
	sw3_node.get_interface("port-channel","1").connect_to(sw6_node.get_interface("port-channel","1"))
	sw3_node.get_interface("port-channel","2").connect_to(sw4_node.get_interface("port-channel","2"))

def sw3_additional_config(node: Node):
	if node.hostname != 'sw3':
		LOGGER.error('{node.hostname} additional config was passed another node.')
		return
	LOGGER.debug(f'{node.hostname} has no additional config at the moment.')
	return