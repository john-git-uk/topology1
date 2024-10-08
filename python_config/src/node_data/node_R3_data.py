from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import logging
LOGGER = logging.getLogger('my_logger')
def R3_Structures(topology: Topology):
	LOGGER.debug("Loading R3 Structures")

	for segs in topology.access_segments:
		if(segs.name == "outreach"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	machine_data=get_machine_data("vios-adventerprisek9-m.SPA.159-3.M6")
	if(machine_data is None):
		raise ValueError("Machine data not found")
		
	node_R3_i1=Interface(
		name="e0/0",
		description="",
		ipv4_address="10.111.10.30",
		ipv4_cidr=31,
		ospf_participant=False,
		ospf_passive=True,
		#ipv6_address=""
	)
	node_R3_i2=Interface(
		name="e0/1",
		description="Connected to SW7 via Subinterfaces",
		ospf_participant=False,
		ospf_passive=True,
		#ipv4_address="",
		#ipv4_cidr=31,
		#ipv6_address=""
	)
	node_R3_i3=Interface(
		name="e0/1.10",
		description="",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.10.254",
		ipv4_cidr=25,
	)
	node_R3_i4=Interface(
		name="e0/1.20",
		description="",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.22.254",
		ipv4_cidr=24,
	)
	node_R3_i5=Interface(
		name="e0/1.30",
		description="",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.30.254",
		ipv4_cidr=25,
	)
	node_R3_i6=Interface(
		name="e0/1.40",
		description="",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.40.254",
		ipv4_cidr=25,
	)
	node_R3_i7=Interface(
		name="e0/3",
		description="Out of band",
		ospf_participant=False,
		ospf_passive=True,
		ipv4_address="192.168.250.3",
		ipv4_cidr=24,
	)
	node_R3_i8=Interface(
		name="loop 0",
		description="l0",
		ospf_participant=True,
		ospf_passive=True,
		ipv4_address="10.133.2.3",
		ipv4_cidr=32,
		#ipv6_address=""
	)
	node_R3_i9=Interface(
		name="tunnel 0",
		description="tunnel to R1 via IPsec",
		ospf_participant=True,
		ospf_passive=False,
		ipv4_address="10.133.2.69",
		ipv4_cidr=31,
	)
	node_R3_i10=Interface(
		name="tunnel 1",
		description="tunnel to R2 via IPsec",
		ospf_participant=True,
		ospf_passive=False,
		ipv4_address="10.133.2.71",
		ipv4_cidr=31,
	)
	node_R3=Node(
		hostname="R3",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_R3_i7

	)
	node_R3.add_interface(node_R3_i1)
	node_R3.add_interface(node_R3_i2)
	node_R3.add_interface(node_R3_i3)
	node_R3.add_interface(node_R3_i4)
	node_R3.add_interface(node_R3_i5)
	node_R3.add_interface(node_R3_i6)
	node_R3.add_interface(node_R3_i7)
	node_R3.add_interface(node_R3_i8)
	node_R3.add_interface(node_R3_i9)
	node_R3.add_interface(node_R3_i10)
	access_segment.nodes.append(node_R3)
	topology.add_node(node_R3)
def R3_relations(topology: Topology):
	LOGGER.debug("Loading R3 Relations")
	topology.get_node("R3").get_interface("e0/0").connect_to(topology.get_node("ISP").get_interface("e0/2"))
	topology.get_node("R3").get_interface("e0/1").connect_to(topology.get_node("SW7").get_interface("e0/0"))
	topology.get_node("R3").get_interface("e0/1.10").connect_to(topology.get_node("SW7").get_interface("e0/0"))
	topology.get_node("R3").get_interface("e0/1.20").connect_to(topology.get_node("SW7").get_interface("e0/0"))
	topology.get_node("R3").get_interface("e0/1.30").connect_to(topology.get_node("SW7").get_interface("e0/0"))
	topology.get_node("R3").get_interface("e0/1.40").connect_to(topology.get_node("SW7").get_interface("e0/0"))
	topology.get_node("R3").get_interface("e0/3").connect_to(topology.exit_interface_oob)
	topology.get_node("R3").get_interface("tunnel 0").tunnel_destination=topology.get_node("R1").get_interface("g2")
	topology.get_node("R3").get_interface("tunnel 1").tunnel_destination=topology.get_node("R2").get_interface("e0/1")
	topology.get_node("R3").get_interface("tunnel 0").connect_to(topology.get_node("R1").get_interface("tunnel 0"))
	topology.get_node("R3").get_interface("tunnel 1").connect_to(topology.get_node("R2").get_interface("tunnel 0"))