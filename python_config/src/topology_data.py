from __future__ import annotations
import ipaddress
from machine_data import get_machine_data
import logging
import os
LOGGER = logging.getLogger('my_logger')

#sys.setrecursionlimit(500)  # Set a lower recursion limit


def main_structures(topology: Topology):
	from node import Node
	from interface import Interface
	from vlan import VLAN
	
	alpouter_eth_out0=Interface(
		name="eth_out0", # This is a fake interface
		description="",
		ipv4_address="192.168.2.246",
		ipv4_cidr=24
		#ipv6_address=ipaddress.IPv6Address(),
		#ipv6_cidr=128
	)
	alpouter_eth_int0=Interface(
		name="eth_int0", # This is a fake interface
		description="",
		ipv4_address="10.111.111.111",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::fff6"),
		ipv6_cidr=128
	)
	alpouter=Node(
		hostname="alpouter",
		machine_data=get_machine_data("alpine"),
		local_user="auto",
		local_password="otua",
		interfaces=[alpouter_eth_int0],
		oob_interface=alpouter_eth_out0,
	)
	topology.domain_name_a = "tapeitup"
	topology.domain_name_b = "private"
	topology.vlans = []
	topology.nodes = []
	topology.exit_interface_main=alpouter_eth_int0
	topology.exit_interface_oob=alpouter_eth_int0
	topology.add_node(alpouter)
	############################################################################
	vlan_10 = VLAN(
		number=10,
		name="sales",
		main_ipv4_netid="10.133.10.0",
		main_ipv4_cidr=25,
		main_fhrp0_ipv4_address="10.133.10.126",
		main_dhcp_exclusion_start=[ipaddress.ip_address("10.133.10.120")],
		main_dhcp_exclusion_end=[ipaddress.ip_address("10.133.10.126")],
		outreach_ipv4_netid="10.133.10.128",
		outreach_ipv4_cidr=25,
		outreach_dhcp_exclusion_start=[ipaddress.ip_address("10.133.10.250")],
		outreach_dhcp_exclusion_end=[ipaddress.ip_address("10.133.10.255")],
	)
	vlan_20 = VLAN(
		number=20,
		name="guest",
		main_ipv4_netid="10.133.20.0",
		main_ipv4_cidr=23,
		main_fhrp0_ipv4_address="10.133.21.254",
		main_dhcp_exclusion_start=[ipaddress.ip_address("10.133.21.240")],
		main_dhcp_exclusion_end=[ipaddress.ip_address("10.133.21.255")],
		outreach_ipv4_netid="10.133.22.0",
		outreach_ipv4_cidr=24,
		outreach_dhcp_exclusion_start=[ipaddress.ip_address("10.133.22.245")],
		outreach_dhcp_exclusion_end=[ipaddress.ip_address("10.133.22.255")],
	)
	vlan_30 = VLAN(
		number=30,
		name="management",
		main_ipv4_netid="10.133.30.0",
		main_ipv4_cidr=25,
		main_fhrp0_ipv4_address="10.133.30.126",
	)
	vlan_40 = VLAN(
		number=40,
		name="supervisor",
		main_ipv4_netid="10.133.40.0",
		main_ipv4_cidr=25,
		main_fhrp0_ipv4_address="10.133.40.126",
	)
	vlan_50 = VLAN(
		number=50,
		name="voice",
		main_ipv4_netid="10.133.50.0",
		main_ipv4_cidr=25,
	)
	vlan_60 = VLAN(
		number=60,
		name="guest-services",
		main_ipv4_netid="10.133.60.0",
		main_ipv4_cidr=24,
		main_fhrp0_ipv4_address="10.133.60.254",
	)
	vlan_70 = VLAN(
			number=70,
			name="internal-services",
			main_ipv4_netid="10.133.70.0",
			main_ipv4_cidr=24,
			main_fhrp0_ipv4_address="10.133.70.254",
	)
	vlan_80 = VLAN(
			number=80,
			name="accounting",
			main_ipv4_netid="10.133.80.0",
			main_ipv4_cidr=24,
			main_fhrp0_ipv4_address="10.133.80.254",
	)
	vlan_250 = VLAN(
			number=250,
			name="oob",
			main_ipv4_netid="10.133.250.0",
			main_ipv4_cidr=24,
	)
	topology.add_vlan(vlan_10)
	topology.add_vlan(vlan_20)
	topology.add_vlan(vlan_30)
	topology.add_vlan(vlan_40)
	topology.add_vlan(vlan_50)
	topology.add_vlan(vlan_60)
	topology.add_vlan(vlan_70)
	topology.add_vlan(vlan_80)
	topology.add_vlan(vlan_250)
	############################################################################
	radius_server_interface_eth1=Interface(  # noqa: F841
		name="eth1",
		ipv4_address="10.131.70.251",
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

	ldap_server_interface_eth1=Interface(  # noqa: F841
		name="eth1",
		ipv4_address="10.131.70.250",
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

	aaa_server_interface_eth1=Interface(  # noqa: F841
		name="eth1",
		ipv4_address="10.131.70.251",
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
	prox1_interface_vi_oob = {
		"name": "vi_oob",
		"ipv4_address": "192.168.2.239",
		"ipv4_cidr": 24,
		"mac_address": "52:54:00:24:15:df"
	}

	prox1_interface_vi_vlan60 = {  # noqa: F841
		"name": "vi_vlan60",
		"ipv4_address": None,  # No IPv4 address assigned
		"ipv6_address": "fe80::5054:ff:fe9e:ab06/64",
		"mac_address": "52:54:00:9e:ab:08"
	}

	prox1_interface_vi_vlan70 = {  # noqa: F841
		"name": "vi_vlan70",
		"ipv4_address": "192.168.70.231",
		"ipv4_cidr": 24,
		"ipv6_address": "fe80::5054:ff:fe9e:ab08/64",
		"mac_address": "52:54:00:9e:ab:08"
	}
	prox1=Node(
		hostname="prox1",
		machine_data=get_machine_data("proxmox"),
		local_user="root",
		local_password="toorp",
		interfaces=[],
		hypervisor_telnet_port=0,
		oob_interface=prox1_interface_vi_oob,
	)
	prox1.config_path=os.path.abspath("../node_config/server/prox1")
	prox1.config_copying_paths = []
	topology.add_node(prox1)
	return topology
def main_relations(topology: Topology):
	topology.get_vlan("sales").main_fhrp0_priority=topology.get_node("SW3").get_interface("vlan 10")
	topology.get_vlan("sales").main_dhcp_interface=topology.get_node("SW3").get_interface("l0")
	topology.get_vlan("sales").outreach_dhcp_interface=topology.get_node("SW3").get_interface("l0")

	topology.get_vlan("guest").main_fhrp0_priority=topology.get_node("SW4").get_interface("vlan 20")
	topology.get_vlan("guest").main_dhcp_interface=topology.get_node("SW3").get_interface("l0")
	topology.get_vlan("guest").outreach_dhcp_interface=topology.get_node("SW3").get_interface("l0")

	topology.get_vlan("management").main_fhrp0_priority=topology.get_node("SW4").get_interface("vlan 30")
	topology.get_vlan("supervisor").main_fhrp0_priority=topology.get_node("SW3").get_interface("vlan 40")
	topology.get_vlan("guest-services").main_fhrp0_priority=topology.get_node("SW3").get_interface("vlan 60")
	topology.get_vlan("internal-services").main_fhrp0_priority=topology.get_node("SW4").get_interface("vlan 70")
	topology.get_vlan("accounting").main_fhrp0_priority=topology.get_node("SW4").get_interface("vlan 80")
	LOGGER.debug(str(len(topology.nodes)))
