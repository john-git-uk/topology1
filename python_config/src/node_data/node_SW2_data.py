from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
LOGGER = logging.getLogger('my_logger')
def SW2_Structures(topology: Topology):
	LOGGER.debug("Loading SW1 Structures")
	machine_data=get_machine_data("viosl2-adventerprisek9-m.ssa.high_iron_20200929")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_SW2_i1=Interface(
		name="e0/0",
		trunk=True,
		vlans=[
			topology.get_vlan("sales"),
			topology.get_vlan("guest"),
			topology.get_vlan("management"),
			topology.get_vlan("supervisor")#,
			#topology.get_vlan("voice")
		]
	)
	node_SW2_i2=Interface(
		name="e0/1",
		trunk=False,
		vlans=[topology.get_vlan("sales")]
	)
	node_SW2_i3=Interface(
		name="e0/2",
		trunk=True,
		vlans=[
			topology.get_vlan("sales"),
			topology.get_vlan("guest"),
			topology.get_vlan("management"),
			topology.get_vlan("supervisor"),
			#topology.get_vlan("voice")
			topology.get_vlan("accounting")
		]
	)
	node_SW2_i4=Interface(
		name="e0/3",
		trunk=True,
		vlans=[
			topology.get_vlan("sales"),
			topology.get_vlan("guest"),
			topology.get_vlan("management"),
			topology.get_vlan("supervisor"),
			#topology.get_vlan("voice")
			topology.get_vlan("accounting")
		]
	)
	node_SW2_i5=Interface(
		name="e1/0",
		trunk=False,
		vlans=[topology.get_vlan("sales")]
	)
	node_SW2_i6=Interface(
		name="e1/1",
		trunk=False,
		vlans=[topology.get_vlan("supervisor")]
	)
	node_SW2_i7=Interface(
		name="e1/2",
		trunk=False,
		vlans=[topology.get_vlan("sales")]
	)
	node_SW2_i8=Interface(
		name="e1/3",
		trunk=False,
		vlans=[topology.get_vlan("guest")]
	)
	node_SW2_i9=Interface(
		name="e2/0",
		trunk=False,
		vlans=[topology.get_vlan("guest")]
	)
	node_SW2_i10=Interface(
		name="e2/1",
		trunk=False,
		vlans=[topology.get_vlan("guest")]
	)
	node_SW2_i11=Interface(
		name="e2/2",
		trunk=False,
		vlans=[topology.get_vlan("accounting")]

	)
	node_SW2_i12=Interface(
		name="e2/3",
		trunk=False,
		vlans=[topology.get_vlan("guest")]
	)
	node_SW2_i13=Interface(
		name="e3/3",
		description="out of band",
		ipv4_address="192.168.250.52",
		ipv4_cidr=24
	)
	node_SW2_i14=Interface(
		name="l0",
		description="",
		ipv4_address="10.133.2.12",
		ipv4_cidr=32
	)
	node_SW2=Node(
		hostname="SW2",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_SW2_i13
	)
	node_SW2.add_interface(node_SW2_i1)
	node_SW2.add_interface(node_SW2_i2)
	node_SW2.add_interface(node_SW2_i3)
	node_SW2.add_interface(node_SW2_i4)
	node_SW2.add_interface(node_SW2_i5)
	node_SW2.add_interface(node_SW2_i6)
	node_SW2.add_interface(node_SW2_i7)
	node_SW2.add_interface(node_SW2_i8)
	node_SW2.add_interface(node_SW2_i9)
	node_SW2.add_interface(node_SW2_i10)
	node_SW2.add_interface(node_SW2_i11)
	node_SW2.add_interface(node_SW2_i12)
	node_SW2.add_interface(node_SW2_i13)
	node_SW2.add_interface(node_SW2_i14)

	topology.add_node(node_SW2)

def SW2_relations(topology: Topology):
	LOGGER.debug("Loading SW2 Relations")
	topology.get_node("SW2").get_interface("e0/0").connect_to(topology.get_node("SW4").get_interface("e1/0"))
	topology.get_node("SW2").get_interface("e0/2").connect_to(topology.get_node("SW1").get_interface("e0/2"))
	topology.get_node("SW2").get_interface("e0/3").connect_to(topology.get_node("SW3").get_interface("e3/0"))
	topology.get_node("SW2").get_interface("e3/3").connect_to(topology.exit_interface_oob)
