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
	
	#alpouter_eth_out0=Interface(
	#	name="eth_out0", # This is a fake interface
	#	description="",
	#	ipv4_address="192.168.2.246",
	#	ipv4_cidr=24
	#	#ipv6_address=ipaddress.IPv6Address(),
	#	#ipv6_cidr=128
	#)
	topology_exit_main=Interface(
		name="eth_int0",
		description="",
		ipv4_address="10.111.111.111",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fff6"),
		ipv6_cidr=128
	)
	topology_exit_oob=Interface(
		name="oob", # This is a fake interface
		description="",
		ipv4_address="192.168.250.254",
		ipv4_cidr=24,
	)
	fake_node=Node(
		hostname="fake",
		machine_data=get_machine_data("alpine"),
		local_user="",
		local_password="",
	)
	fake_node.add_interface(topology_exit_main)
	fake_node.add_interface(topology_exit_oob)
	topology.domain_name_a = "tapeitup"
	topology.domain_name_b = "private"
	topology.dns_ipv4_address=ipaddress.IPv4Address("8.8.8.8")
	topology.exit_interface_main=topology_exit_main
	topology.exit_interface_oob=topology_exit_oob
	topology.add_node(fake_node)
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
	############################################################################
	### This is old docker node
	radius_server_interface_eth1=Interface(  # noqa: F841
		name="eth1",
		ipv4_address="10.133.70.251",
		ipv4_cidr=24
	)
	radius_server_interface_eth2=Interface(
		name="eth2",
		ipv4_address="192.168.250.101",
		ipv4_cidr=24
	)
	radius_server=Node(
		hostname="radius_server",
		machine_data=get_machine_data("debian"),
		local_user="root",
		local_password="",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=radius_server_interface_eth2,
	)
	radius_server.config_path=os.path.abspath("../node_config/server/radius_server")
	LOGGER.debug("radius_server.config_path: "+radius_server.config_path)
	radius_server.config_copying_paths = [
		{"source": radius_server.config_path+"/clients.conf", "dest": "/etc/freeradius/3.0/clients.conf"},
		{"source": radius_server.config_path+"/authorize", "dest": "/etc/freeradius/3.0/mods-config/files/authorize"},
		{"source": radius_server.config_path+"/networkconfig.sh", "dest": "/sbin/scripts/networkconfig.sh"},
		{"source": radius_server.config_path+"/sshd_config", "dest": "/etc/ssh/sshd_config"},
		{"source": radius_server.config_path+"/starter.sh", "dest": "/sbin/scripts/starter.sh"},
	]
	topology.add_node(radius_server)
	############################################################################
	### This is old docker node
	ldap_server_interface_eth1=Interface(  # noqa: F841
		name="eth1",
		ipv4_address="10.133.70.250",
		ipv4_cidr=24
	)
	ldap_server_interface_eth2=Interface(
		name="eth2",
		ipv4_address="192.168.250.102",
		ipv4_cidr=24
	)
	ldap_server=Node(
		hostname="ldap_server",
		machine_data=get_machine_data("debian"),
		local_user="root",
		local_password="",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=ldap_server_interface_eth2,
	)
	ldap_server.config_path=os.path.abspath("../node_config/server/ldap_server")
	ldap_server.config_copying_paths = [
		{"source": ldap_server.config_path+"/runonce.conf", "dest": "/sbin/scripts/runonce.sh"},
		{"source": ldap_server.config_path+"/networkconfig.sh", "dest": "/sbin/scripts/networkconfig.sh"},
		{"source": ldap_server.config_path+"/sshd_config", "dest": "/etc/ssh/sshd_config"},
		{"source": ldap_server.config_path+"/starter.sh", "dest": "/sbin/scripts/starter.sh"},
		{"source": ldap_server.config_path+"/config.php", "dest": "/etc/phpldapadmin/config.php"},
		{"source": ldap_server.config_path+"/base.ldif", "dest": "/root/base.ldif"},
		{"source": ldap_server.config_path+"/ldap_setup.sh", "dest": "/sbin/scripts/ldap_setup.sh"},
		{"source": ldap_server.config_path+"/ldap_build.sh", "dest": "/sbin/scripts/ldap_build.sh"},
		{"source": ldap_server.config_path+"/ldap_build.sh", "dest": "/sbietc/nslcd.conf"},
		{"source": ldap_server.config_path+"/ldap_build.sh", "dest": "/etc/nslcd.conf"},
		{"source": ldap_server.config_path+"/ldap_build.sh", "dest": "/etc/nsswitch.conf"},
		{"source": ldap_server.config_path+"/logging.ldif", "dest": "/root/logging.ldif"}
	]
	topology.add_node(ldap_server)
	############################################################################
	### This is old docker node
	aaa_server_interface_eth1=Interface(  # noqa: F841
		name="eth1",
		ipv4_address="10.133.70.251",
		ipv4_cidr=24
	)
	aaa_server_interface_eth2=Interface(
		name="eth2",
		ipv4_address="192.168.250.101",
		ipv4_cidr=24
	)
	aaa_server=Node(
		hostname="aaa_server",
		machine_data=get_machine_data("ubuntu"),
		local_user="root",
		local_password="",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=aaa_server_interface_eth2,
	)
	aaa_server.config_path=os.path.abspath("../node_config/server/aaa_server")
	aaa_server.config_copying_paths = [
		{"source": aaa_server.config_path+"/clients.conf", "dest": "/etc/freeradius/3.0/clients.conf"},
		{"source": aaa_server.config_path+"/authorize", "dest": "/etc/freeradius/3.0/mods-config/files/authorize"},
		{"source": aaa_server.config_path+"/tac_plus.conf", "dest": "/etc/tacacs+/tac_plus.conf"},
		{"source": aaa_server.config_path+"/networkconfig.sh", "dest": "/sbin/scripts/networkconfig.sh"},
		{"source": aaa_server.config_path+"/sshd_config", "dest": "/etc/ssh/sshd_config"},
		{"source": aaa_server.config_path+"/starter.sh", "dest": "/sbin/scripts/starter.sh"},
	]
	topology.add_node(aaa_server)
	############################################################################
	prox1_interface_oob_hitch = Interface (
		name= "oob_hitch",
		ipv4_address= "192.168.2.239",
		ipv4_cidr= 24,
	)
	prox1_interface_vmbr60 = Interface (
		name= "vmbr60",
		ipv4_address= "10.133.60.245",
		ipv4_cidr= 24,
	)
	prox1_interface_vmbr70 = Interface (
		name= "vmbr70",
		ipv4_address= "10.133.70.245",
		ipv4_cidr= 24,
	)
	prox1_interface_enp1s0 = Interface (
		name= "enp1s0",
	)
	prox1_interface_enp2s0 = Interface (
		name= "enp2s0",
	)
	prox1=Node(
		hostname="prox1",
		machine_data=get_machine_data("proxmox"),
		local_user="root",
		local_password="toorp",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=prox1_interface_oob_hitch,
	)
	prox1.add_interface(prox1_interface_oob_hitch)
	prox1.add_interface(prox1_interface_vmbr60)
	prox1.add_interface(prox1_interface_vmbr70)
	prox1.add_interface(prox1_interface_enp1s0)
	prox1.add_interface(prox1_interface_enp2s0)
	# TODO: Forget the other interfaces for now
	prox1.config_path=os.path.abspath("../node_config/server/prox1")
	prox1.config_copying_paths = []
	topology.add_node(prox1)
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
	main.get_vlan("sales").fhrp0_priority=topology.get_node("SW3").get_interface("vlan 10")
	main.get_vlan("sales").dhcp_interface=topology.get_node("SW3").get_interface("l0")
	outreach.get_vlan("sales").dhcp_interface=topology.get_node("SW3").get_interface("l0")

	main.get_vlan("guest").fhrp0_priority=topology.get_node("SW4").get_interface("vlan 20")
	main.get_vlan("guest").dhcp_interface=topology.get_node("SW3").get_interface("l0")
	outreach.get_vlan("guest").dhcp_interface=topology.get_node("SW3").get_interface("l0")

	main.get_vlan("management").fhrp0_priority=topology.get_node("SW4").get_interface("vlan 30")
	main.get_vlan("supervisor").fhrp0_priority=topology.get_node("SW3").get_interface("vlan 40")
	main.get_vlan("guest-services").fhrp0_priority=topology.get_node("SW3").get_interface("vlan 60")
	main.get_vlan("internal-services").fhrp0_priority=topology.get_node("SW4").get_interface("vlan 70")
	main.get_vlan("accounting").fhrp0_priority=topology.get_node("SW4").get_interface("vlan 80")

	topology.get_access_segment("outreach").get_vlan("sales").dhcp_interface=topology.get_node("R3").get_interface("e0/1.10")
	topology.get_access_segment("outreach").get_vlan("sales").dhcp_interface=topology.get_node("R3").get_interface("e0/1.20")
	topology.get_access_segment("outreach").get_vlan("sales").dhcp_interface=topology.get_node("R3").get_interface("e0/1.40")
	
	topology.ntp_master=topology.get_node("R1").get_interface("loop 0")
	topology.ntp_public=ipaddress.IPv4Address("1.1.1.1")

	topology.get_node("prox1").get_interface("enp1s0").connect_to(topology.exit_interface_oob)
	topology.get_node("prox1").get_interface("enp2s0").connect_to(topology.get_node("SW6").get_interface("e2/0"))
	# TODO: Add the other interfaces for prox1