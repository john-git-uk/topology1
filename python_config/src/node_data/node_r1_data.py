from __future__ import annotations
from interface import Interface
from node import Node
from topology import Topology
from machine_data import get_machine_data
import ipaddress
import logging
from project_globals import GLOBALS
from handle_cisco import cisco_replace_ethernet_with_gigabit
import subprocess
LOGGER = logging.getLogger('my_logger')
def r1_Structures(topology: Topology):
	LOGGER.debug("Loading r1 Structures")

	using_csr_image_instead_of_iou = True
	if using_csr_image_instead_of_iou:
		machine_data=get_machine_data('Cisco Catalyst 8000V 17.09.01a 8G')
	else:
		machine_data=get_machine_data('Cisco IOU L3 17.12.1')
	if(machine_data is None):
		raise ValueError("Machine data not found")
	if machine_data.gigabit_naming:
		node_r1_i1=Interface(
			name ="1",
			interface_type="gigabitethernet",
			description="Connected to sw3",
			ipv4_address="10.133.2.64",
			ipv4_cidr=31,
			ospf_participant=True,
			ospf_passive=False,
			#ipv6_address="",
			#ipv6_cidr=127
		)
		node_r1_i2=Interface(
			name ="2",
			interface_type="gigabitethernet",
			description="Connected to ISP",
			ipv4_address="10.111.10.10",
			ipv4_cidr=31,
			ospf_participant=True,
			ospf_passive=True,
			ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::ffff"),
			ipv6_cidr=127
		)
		node_r1_i3=Interface(
			name ="3",
			interface_type="gigabitethernet",
			description="Connected to sw4",
			ipv4_address="10.133.2.72",
			ipv4_cidr=31,
			ospf_participant=True,
			ospf_passive=False,
			#ipv6_address="",
			#ipv6_cidr=127
		)
		node_r1_i4=Interface(
			name ="4",
			interface_type="gigabitethernet",
			description="Out of band",
			ipv4_address="192.168.250.1",
			ipv4_cidr=24,
			ospf_participant=False,
			ospf_passive=True,
			#ipv6_cidr=127
		)
	else:
		node_r1_i1=Interface(
			name ="0/0",
			interface_type="ethernet",
			description="Connected to sw3",
			ipv4_address="10.133.2.64",
			ipv4_cidr=31,
			ospf_participant=True,
			ospf_passive=False,
			#ipv6_address="",
			#ipv6_cidr=127
		)
		node_r1_i2=Interface(
			name ="0/1",
			interface_type="ethernet",
			description="Connected to ISP",
			ipv4_address="10.111.10.10",
			ipv4_cidr=31,
			ospf_participant=True,
			ospf_passive=True,
			ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::ffff"),
			ipv6_cidr=127
		)
		node_r1_i3=Interface(
			name ="0/2",
			interface_type="ethernet",
			description="Connected to sw4",
			ipv4_address="10.133.2.72",
			ipv4_cidr=31,
			ospf_participant=True,
			ospf_passive=False,
			#ipv6_address="",
			#ipv6_cidr=127
		)
		node_r1_i4=Interface(
			name ="0/3",
			interface_type="ethernet",
			description="Out of band",
			ipv4_address="192.168.250.1",
			ipv4_cidr=24,
			ospf_participant=False,
			ospf_passive=True,
			#ipv6_cidr=127
		)
	
	node_r1_i5=Interface(
		name ="0",
		interface_type="loopback",
		description="l0",
		ipv4_address="10.133.2.1",
		ipv4_cidr=32,
		ospf_participant=True,
		ospf_passive=True,
		#ipv6_address="",
		#ipv6_cidr=127
	)
	node_r1_i6=Interface(
		name ="0",
		interface_type="tunnel",
		description="tunnel to r3 via IPsec",
		ipv4_address="10.133.2.68",
		ipv4_cidr=31,
		ospf_participant=True,
		ospf_passive=False,
		#ipv6_address="",
		#ipv6_cidr=127
	)
		
	node_r1=Node(
		hostname ="r1",
		local_user=GLOBALS.r1_username,
		local_password=GLOBALS.r1_password,
		machine_data=machine_data,
		oob_interface=node_r1_i4,
		identity_interface=node_r1_i5,
		additional_config=r1_additional_config
	)
	node_r1.add_interface(node_r1_i1)
	node_r1.add_interface(node_r1_i2)
	node_r1.add_interface(node_r1_i3)
	node_r1.add_interface(node_r1_i4)
	node_r1.add_interface(node_r1_i5)
	node_r1.add_interface(node_r1_i6)
	topology.add_node(node_r1)

def r1_relations(topology: Topology):
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
	LOGGER.debug("Loading r1 Relations")
	if r1_node.machine_data.gigabit_naming:
		r1_node.get_interface("gigabitethernet","1").connect_to(topology.get_node("sw3").get_interface("ethernet","1/3"))
		r1_node.get_interface("gigabitethernet","2").connect_to(topology.get_exit_interface("exit_r1"))
		r1_node.get_interface("gigabitethernet","3").connect_to(topology.get_node("sw4").get_interface("ethernet","2/1"))
		r1_node.get_interface("gigabitethernet","4").connect_to(topology.get_exit_interface('exit_oob'))
	else:
		r1_node.get_interface("ethernet","0/0").connect_to(topology.get_node("sw3").get_interface("ethernet","1/3"))
		r1_node.get_interface("ethernet","0/1").connect_to(topology.get_exit_interface("exit_r1"))
		r1_node.get_interface("ethernet","0/2").connect_to(topology.get_node("sw4").get_interface("ethernet","2/1"))
		r1_node.get_interface("ethernet","0/3").connect_to(topology.get_exit_interface('exit_oob'))

	r1_node.get_interface("tunnel","0").tunnel_destination=(topology.get_node("r3").get_interface("ethernet","0/0"))
	r1_node.get_interface("tunnel","0").connect_to(topology.get_node("r3").get_interface("tunnel","0"))

def r1_additional_config(node: Node):
	if node.hostname != 'r1':
		LOGGER.error('{node.hostname} additional config was passed another node.')
		return

	#r1_CA_Config(node)
	# Add additional config before this.
	##########################################################
	# If This Debug Flag Is Set To True It Will Replace All Ethernet Interfaces With Gigabit Interfaces
	# This is for testing different router images
	#if True or gigabit_rename:
	#	cisco_replace_ethernet_with_gigabit(node)
	##########################################################
	return

def r1_CA_Config(node: Node):
	if node.hostname != 'r1':
		LOGGER.error('{node.hostname} additional config was passed another node.')
		return
	if node.additional_config is None:
		node.additional_config = []
	
	if (node.machine_data.device_type != 'cisco_ios'
	and node.machine_data.device_type != 'cisco_xe'):
		return
	#################################################################
	from genie.conf import Genie
	from genie.libs.parser.utils import get_parser
	from genie.testbed import load

	# Load your testbed YAML file for device information
	node.topology_a_part_of.make_genie_yaml()
	testbed = load(GLOBALS.testbed_path)

	# Connect to the device
	device = testbed.devices[node.hostname]
	
	subprocess.run(f'ssh-keygen -f "$HOME/.ssh/known_hosts" -R "{(str)(node.oob_interface.ipv4_address)}"', shell=True)
	try:
		device.connect()
	except Exception as e:
		LOGGER.error(f"Failed to connect to {node.hostname}: {e}")
		return

	# Send command and parse
	genie_output = device.parse('show file systems')
	LOGGER.debug(f"Genie output: {genie_output}")

	device.disconnect()

	database_path = None
	# for each file system
	for fs_id, file_system in genie_output.get('file_systems', {}).items():
		# search the multiple prefixs for unix: or flash:
		if "unix:" in file_system.get('prefixes', ''):
			LOGGER.debug(f"Found unix")
			database_path = 'unix:ca'
		elif "flash:" in file_system.get('prefixes', ''):
			LOGGER.debug(f"Found flash")
			database_path = 'flash:ca'
	if database_path is None:
		LOGGER.warning(f'Was unable to automaticly decide filesystem to store CA data for {node.hostname}')
		return

	node.additional_config_commands.append('!!!!!!!!!!!!!!!!!!!!!!!!!!')
	node.additional_config_commands.append('!!!!!!! CA Config  !!!!!!!')
	node.additional_config_commands.append(f'crypto pki server {node.hostname}-ca')
	node.additional_config_commands.append(f'do mkdir {database_path}')
	node.additional_config_commands.append(f'database url {database_path}')
	node.additional_config_commands.append('database level complete')
	node.additional_config_commands.append('issuer-name CN=r1-CA,O=tapeitup.private')
	node.additional_config_commands.append('grant auto')
	node.additional_config_commands.append('lifetime ca-certificate 7300')
	node.additional_config_commands.append('lifetime certificate 3650')
	node.additional_config_commands.append('no shut')
	# !sevenwsad

	node.additional_config_commands.append('crypto pki trustpoint https-cert')
	node.additional_config_commands.append(f'enrollment url http://{node.get_interface('loopback','0').ipv4_address}')
	node.additional_config_commands.append('revocation check none')
	node.additional_config_commands.append('exit')
	node.additional_config_commands.append('crypto pki enroll https-cert')
	node.additional_config_commands.append('ip http secure-server')
	node.additional_config_commands.append('ip http client source-interface loopback 0')
	node.additional_config_commands.append('no ip http server')
	node.additional_config_commands.append('ip http secure-trustpoint https-cert')

	node.additional_config_commands.append('!!!!!!!!!!!!!!!!!!!!!!!!!!')