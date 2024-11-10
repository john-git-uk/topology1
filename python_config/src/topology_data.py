from __future__ import annotations
import ipaddress
import logging
import os
from machine_data import get_machine_data

LOGGER = logging.getLogger('my_logger')

def main_structures(topology: Topology):
	from node import Node
	from interface import Interface
	from vlan import VLAN
	from access_segment import AccessSegment
	from access_control import Access_Control
	
	#alpouter_eth_out0=Interface(
	#	name="eth_out0", # This is a fake interface
	#	description="",
	#	ipv4_address="192.168.2.246",
	#	ipv4_cidr=24
	#	#ipv6_address=ipaddress.IPv6Address(),
	#	#ipv6_cidr=128
	#)
	#topology_exit_main=Interface(
	#	name="eth_int0",
	#	interface_type="ethernet",
	#	description="",
	#	ipv4_address="10.111.111.111",
	#	ipv4_cidr=31,
	#	ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fff6"),
	#	ipv6_cidr=128
	#)
	exit_r1=Interface(
		name="exit_r1",
		interface_type="ethernet",
		description="Connected to R1",
		ipv4_address="10.111.10.11",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::ffff"),
		ipv6_cidr=127
	)
	exit_r2=Interface(
		name="exit_r2",
		interface_type="ethernet",
		description="Connected to R2",
		ipv4_address="10.111.10.21",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fffd"),
		ipv6_cidr=127
	)
	exit_r3=Interface(
		name="exit_r3",
		interface_type="ethernet",
		description="Connected to R3",
		ipv4_address="10.111.10.31",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fffb"),
		ipv6_cidr=127
	)
	exit_oob=Interface(
		name="exit_oob", # This is a fake interface for debian pc
		interface_type="ethernet",
		description="",
		ipv4_address="192.168.250.254",
		ipv4_cidr=24,
	)
	#fake_node=Node(
	#	hostname="fake",
	#	machine_data=get_machine_data("alpine"),
	#	local_user="",
	#	local_password="",
	#)
	#fake_node.add_interface(topology_exit_main)
	#fake_node.add_interface(topology_exit_oob)
	topology.domain_name_a = "tapeitup"
	topology.domain_name_b = "private"
	topology.dns_upstream.append(ipaddress.ip_address("8.8.8.8"))
	#topology.exit_interface_main=topology_exit_main
	topology.exit_interfaces.append(exit_r1)
	topology.exit_interfaces.append(exit_r2)
	topology.exit_interfaces.append(exit_r3)
	topology.exit_interfaces.append(exit_oob)
	#topology.add_node(fake_node)
	main_access_segment = AccessSegment(
		name="main",
	)
	outreach_access_segment = AccessSegment(
		name="outreach",
	)
	topology.access_segments.append(main_access_segment)
	topology.access_segments.append(outreach_access_segment)
	############################################################################
	vlan_10 = VLAN(
		number=10,
		name="sales",
		ipv4_netid="10.133.10.0",
		ipv4_cidr=25,
		fhrp0_ipv4_address="10.133.10.126",
		dhcp_exclusion_start=[ipaddress.ip_address("10.133.10.120")],
		dhcp_exclusion_end=[ipaddress.ip_address("10.133.10.126")],
	)
	vlan_20 = VLAN(
		number=20,
		name="guest",
		ipv4_netid="10.133.20.0",
		ipv4_cidr=23,
		fhrp0_ipv4_address="10.133.21.254",
		dhcp_exclusion_start=[ipaddress.ip_address("10.133.21.240")],
		dhcp_exclusion_end=[ipaddress.ip_address("10.133.21.255")],
	)
	vlan_30 = VLAN(
		number=30,
		name="management",
		ipv4_netid="10.133.30.0",
		ipv4_cidr=25,
		fhrp0_ipv4_address="10.133.30.126",
	)
	vlan_40 = VLAN(
		number=40,
		name="supervisor",
		ipv4_netid="10.133.40.0",
		ipv4_cidr=25,
		fhrp0_ipv4_address="10.133.40.126",
		dhcp_exclusion_start=[ipaddress.ip_address("10.133.40.120")],
		dhcp_exclusion_end=[ipaddress.ip_address("10.133.40.126")],
	)
	vlan_50 = VLAN(
		number=50,
		name="voice",
		ipv4_netid="10.133.50.0",
		ipv4_cidr=25,
	)
	vlan_60 = VLAN(
		number=60,
		name="guest-services",
		ipv4_netid="10.133.60.0",
		ipv4_cidr=24,
		fhrp0_ipv4_address="10.133.60.254",
	)
	vlan_70 = VLAN(
		number=70,
		name="internal-services",
		ipv4_netid="10.133.70.0",
		ipv4_cidr=24,
		fhrp0_ipv4_address="10.133.70.254",
	)
	vlan_80 = VLAN(
		number=80,
		name="accounting",
		ipv4_netid="10.133.80.0",
		ipv4_cidr=24,
		fhrp0_ipv4_address="10.133.80.254",
		dhcp_exclusion_start=[ipaddress.ip_address("10.133.80.225")],
		dhcp_exclusion_end=[ipaddress.ip_address("10.133.80.255")],
	)
	#vlan_250 = VLAN(
	#		number=250,
	#		name="oob",
	#		ipv4_netid="10.133.250.0",
	#		ipv4_cidr=24,
	#)
	main_access_segment.vlans.append(vlan_10)
	main_access_segment.vlans.append(vlan_20)
	main_access_segment.vlans.append(vlan_30)
	main_access_segment.vlans.append(vlan_40)
	main_access_segment.vlans.append(vlan_50)
	main_access_segment.vlans.append(vlan_60)
	main_access_segment.vlans.append(vlan_70)
	main_access_segment.vlans.append(vlan_80)
	#main_access_segment.vlans.append(vlan_250)
	#vlan_250.auto_dhcp_exclude(14)

	ovlan_10 = VLAN(
		number=10,
		name="sales",
		ipv4_netid="10.133.10.128",
		ipv4_cidr=25,
		dhcp_exclusion_start=[ipaddress.ip_address("10.133.10.250")],
		dhcp_exclusion_end=[ipaddress.ip_address("10.133.10.255")],
	)
	ovlan_20 = VLAN(
		number=20,
		name="guest",
		ipv4_netid="10.133.22.0",
		ipv4_cidr=24,
		dhcp_exclusion_start=[ipaddress.ip_address("10.133.22.245")],
		dhcp_exclusion_end=[ipaddress.ip_address("10.133.22.255")],
	)
	ovlan_30 = VLAN(
		number=30,
		name="management",
		ipv4_netid="10.133.30.128",
		ipv4_cidr=25,
	)
	ovlan_40 = VLAN(
		number=40,
		name="supervisor",
		ipv4_netid="10.133.40.128",
		ipv4_cidr=25,
		dhcp_exclusion_start=[ipaddress.ip_address("10.133.40.248")],
		dhcp_exclusion_end=[ipaddress.ip_address("10.133.40.255")],
	)
	outreach_access_segment.vlans.append(ovlan_10)
	outreach_access_segment.vlans.append(ovlan_20)
	outreach_access_segment.vlans.append(ovlan_30)
	outreach_access_segment.vlans.append(ovlan_40)
	
	# Management
	acc1 = Access_Control(
		vlans = [
			vlan_30,
			ovlan_30,
		],
	)
	# Guests
	acc2 = Access_Control(
		vlans = [
			vlan_20,
			ovlan_20,
			vlan_60,
		],
		allowlist = [
			ipaddress.ip_network("0.0.0.0/0"),
		]
	)
	# Sales
	acc3 = Access_Control(
		vlans = [
			vlan_10,
			ovlan_10,
			vlan_60,
		],
		allowlist = [
			ipaddress.ip_network("0.0.0.0/0"),
		]
	)
	# Supervisor
	acc4 = Access_Control(
		vlans = [
			vlan_40,
			ovlan_40,
			vlan_60,
		],
		allowlist = [
			ipaddress.ip_network("0.0.0.0/0"),
		]
	)
	# Accounting
	acc5 = Access_Control(
		vlans = [
			vlan_80,
			ovlan_40,
			vlan_60,
		],
		allowlist = [
			ipaddress.ip_network("0.0.0.0/0"),
		]
	)
	# Internal Services (no internet)
	acc6 = Access_Control(
		vlans = [
			vlan_10,
			ovlan_10,
			vlan_40,
			ovlan_40,
			vlan_80,
			vlan_70,
		],
	)
	topology.access_controls.append(acc1)
	topology.access_controls.append(acc2)
	topology.access_controls.append(acc3)
	topology.access_controls.append(acc4)
	topology.access_controls.append(acc5)
	topology.access_controls.append(acc6)

	return topology
def main_relations(topology: Topology):
	for seg in topology.access_segments:
		if(seg.name == "main"):
			main = seg
		if(seg.name == "outreach"):
			outreach = seg
	if(main is None):
		LOGGER.error("No main access segment found")
		return
	if(outreach is None):
		LOGGER.error("No outreach access segment found")
		return
	topology.dns_private.append((topology.get_node("dns-server-1")).get_interface("ethernet","eth1"))
	main.get_vlan("sales").fhrp0_priority=topology.get_node("SW3").get_interface("vlan","10")
	main.get_vlan("sales").dhcp_interface=topology.get_node("SW3").get_interface("loopback","0")
	outreach.get_vlan("sales").dhcp_interface=topology.get_node("R3").get_interface("ethernet","0/1.10")
	outreach.get_vlan("sales").default_gateway=topology.get_node("R3").get_interface("ethernet","0/1.10")

	main.get_vlan("guest").fhrp0_priority=topology.get_node("SW4").get_interface("vlan","20")
	main.get_vlan("guest").dhcp_interface=topology.get_node("SW3").get_interface("loopback","0")
	outreach.get_vlan("guest").dhcp_interface=topology.get_node("R3").get_interface("ethernet","0/1.20")
	outreach.get_vlan("guest").default_gateway=topology.get_node("R3").get_interface("ethernet","0/1.20")

	main.get_vlan("management").fhrp0_priority=topology.get_node("SW4").get_interface("vlan","30")
	outreach.get_vlan("management").default_gateway=topology.get_node("R3").get_interface("ethernet","0/1.30")

	main.get_vlan("supervisor").fhrp0_priority=topology.get_node("SW3").get_interface("vlan","40")
	outreach.get_vlan("supervisor").default_gateway=topology.get_node("R3").get_interface("ethernet","0/1.40")
	
	main.get_vlan("guest-services").fhrp0_priority=topology.get_node("SW3").get_interface("vlan","60")
	main.get_vlan("internal-services").fhrp0_priority=topology.get_node("SW4").get_interface("vlan","70")
	main.get_vlan("accounting").fhrp0_priority=topology.get_node("SW4").get_interface("vlan","80")

	topology.get_access_segment("outreach").get_vlan("sales").dhcp_interface=topology.get_node("R3").get_interface("ethernet","0/1.10")
	topology.get_access_segment("outreach").get_vlan("sales").dhcp_interface=topology.get_node("R3").get_interface("ethernet","0/1.20")
	topology.get_access_segment("outreach").get_vlan("sales").dhcp_interface=topology.get_node("R3").get_interface("ethernet","0/1.40")
	
	topology.ntp_master=topology.get_node("R1").get_interface("loopback", "0")
	topology.ntp_public=ipaddress.ip_address("1.1.1.1")

	topology.get_exit_interface('exit_r1').connect_to(topology.get_node("R1").get_interface('gigabit ethernet','2'))
	topology.get_exit_interface('exit_r2').connect_to(topology.get_node("R2").get_interface('ethernet','0/1'))
	topology.get_exit_interface('exit_r3').connect_to(topology.get_node("R3").get_interface('ethernet','0/0'))

	topology.certificate_authorities.append(topology.get_node("R1").get_interface("loopback", "0"))