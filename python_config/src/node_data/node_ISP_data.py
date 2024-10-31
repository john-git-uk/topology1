from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import ipaddress
import logging
LOGGER = logging.getLogger('my_logger')
def ISP_Structures(topology: Topology):
	LOGGER.debug("Loading ISP Structures")
	# Warning, currently lacking oob interface
	machine_data=get_machine_data("vios-adventerprisek9-m.SPA.159-3.M6")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_ISP_i1=Interface(
		name="0/0",
		interface_type="ethernet",
		description="Connected to R1",
		ipv4_address="10.111.10.11",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::ffff"),
		ipv6_cidr=127
	)
	node_ISP_i2=Interface(
		name="0/1",
		interface_type="ethernet",
		description="Connected to R2",
		ipv4_address="10.111.10.21",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fffd"),
		ipv6_cidr=127
	)
	node_ISP_i3=Interface(
		name="0/2",
		interface_type="ethernet",
		description="Connected to R3",
		ipv4_address="10.111.10.31",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fffb"),
		ipv6_cidr=127
	)
	#node_ISP_i4=Interface(
	#	name="e0/3",
	#	description="Connected to DEBTOP",
	#	ipv4_address="192.168.2.245",
	#	ipv4_cidr=24,
	#	ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fff9"),
	#	ipv6_cidr=127
	#)
	node_ISP_i5=Interface(
		name="1/0",
		interface_type="ethernet",
		description="Connected to alprouter",
		ipv4_address="10.111.111.110",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fff7"),
		ipv6_cidr=127
	)
	node_ISP=Node(
		hostname="ISP",
		domain_override="ISP",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_ISP_i5
	)
	node_ISP.add_interface(node_ISP_i1)
	node_ISP.add_interface(node_ISP_i2)
	node_ISP.add_interface(node_ISP_i3)
	#node_ISP.add_interface(node_ISP_i4)
	node_ISP.add_interface(node_ISP_i5)
	topology.add_node(node_ISP)
def ISP_relations(topology: Topology):
	LOGGER.debug("Loading ISP Relations")
	topology.get_node("ISP").get_interface("ethernet","0/0").connect_to(topology.get_node("R1").get_interface("gigabit ethernet","2"))
	topology.get_node("ISP").get_interface("ethernet","0/1").connect_to(topology.get_node("R2").get_interface("ethernet","0/0"))
	topology.get_node("ISP").get_interface("ethernet","0/2").connect_to(topology.get_node("R3").get_interface("ethernet","0/0"))
	#topology.get_node("ISP").get_interface("e0/3").connect_to(topology.exit_interface_main)
	topology.get_node("ISP").get_interface("ethernet","1/0").connect_to(topology.exit_interface_main)
