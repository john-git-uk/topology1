from __future__ import annotations
import paramiko
import logging
from convert import get_escaped_string, get_chunky_hex, base64_encode_string
from interface import Interface
from node import Node
from handle_proxmox import Container, execute_proxnode_commands, start_container, wait_for_container_ping_debian, wait_for_container_running
import aiohttp
import asyncio
import pihole as ph
import base64
import time
from pathlib import Path
import os
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def ca_server_1_structures(topology: Topology):
	from machine_data import get_machine_data

	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	ca_server1_i1 = Interface(
		name="eth0",
		interface_type="ethernet",
		description="oob",
		ipv4_address="192.168.250.229",
		ipv4_cidr=24
	)
	ca_server1_i2 = Interface(
		name="eth1",
		interface_type="ethernet",
		ipv4_address="10.133.60.249",
		ipv4_cidr=24
	)
	ca_server1_i3 = Interface(
		name="eth2",
		interface_type="ethernet",
		ipv4_address="10.133.70.249",
		ipv4_cidr=24
	)
	ca_server1_i4 = Interface(
		name="eth3",
		description="management",
		interface_type="ethernet",
		ipv4_address="10.133.30.122",
		ipv4_cidr=25
	)
	ca_server1 = Node(
		hostname="ca-server-1",
		machine_data=get_machine_data("debian"),
		oob_interface=ca_server1_i1,
		identity_interface=ca_server1_i2,
		local_user=GLOBALS.ca_server_1_username,
		local_password=GLOBALS.ca_server_1_password,
		hypervisor_telnet_port=0,
	)
	ca_server1_container = Container(
		ctid=204,
		template="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
		memory=4096,
		cores=4,
		rootfs="local:8",
		resource_pool = "default",
		disk_size=8,
		node_a_part_of=prox1,
		node_data=ca_server1,
	)
	ca_server1.add_interface(ca_server1_i1)
	ca_server1.add_interface(ca_server1_i2)
	ca_server1.add_interface(ca_server1_i3)
	ca_server1.add_interface(ca_server1_i4)
	prox1.topology_a_part_of.add_node(ca_server1)
	prox1.add_container(ca_server1_container)
	access_segment.nodes.append(ca_server1)
	ca_server1.access_segment = access_segment

def ca_server_1_relations(topology: Topology):
	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	ca_server_1 = None
	ca_server_1 = topology.get_node("ca-server-1")
	
	if(ca_server_1 is None):
		raise Exception("ca_server_1 is None")

	ca_server_1.get_interface("ethernet","eth0").connect_to(prox1.get_interface("bridge","oob_hitch"))
	ca_server_1.get_interface("ethernet","eth1").connect_to(prox1.get_interface("bridge","vmbr60"))
	ca_server_1.get_interface("ethernet","eth2").connect_to(prox1.get_interface("bridge","vmbr70"))
	ca_server_1.get_interface("ethernet","eth3").connect_to(prox1.get_interface("bridge","vmbr30"))

def ca_server_1_config(node: Node):
	''' This is where the docstring goes.'''
	#region Debug Help
	'''
# Here is a copy and paste to preinstall packages instead.

apt-get update

apt-get upgrade

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends locales 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends xxd 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends telnet 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-client 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nano 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iputils-ping 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends net-tools 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rsyslog 

env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wget

apt-get install -y openjdk-17-jdk

apt-get install -y ant

apt-get install -y mariadb-server

apt-get install -y mariadb-plugin-connect

apt-get install -y unzip

'''
	#endregion
	from handle_debian.handle_debian import decode_all_base64_in_script, commands_packages_essential
	from handle_debian.pki import paramiko_upload_pki_assets, commands_config_pki_1, commands_config_pki_wildfly_cli, paramiko_retrieve_ejbca_cert,\
		proxmox_check_for_wildfly_cli, generate_local_certificate, generate_local_p12, commands_config_pki_recreate_local_admin,\
			paramiko_retrieve_local_cert, commands_config_pki_ejbca_install, paramiko_check_for_wildfly_cli

	
	topology = None
	prox1 = None
	container = None
	topology = node.topology_a_part_of
	if topology is None:
		LOGGER.error("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		LOGGER.error("prox1 does not exist! Did you try to load in the wrong order?")
		return
	container = prox1.get_container(node.hostname)
	if container is None:
		LOGGER.error("container is None")
		return
	if len(topology.dns_upstream) == 0:
		LOGGER.error(f"topology.dns_upstream is empty. Configuring {node.hostname} requires at least one upstream DNS server")
		return
	if not wait_for_container_running(prox1, container, 30):
		LOGGER.error(f"Container {node.hostname} did not start in time")
		return

	# TODO: Consider placing this in a more "main" function...
	#generate_local_certificate(node)

	# Log file for commands
	out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / node.hostname
	out_path.mkdir(exist_ok=True, parents=True)


	#################################
	commands = []
	allcommands = []
	for upstream in topology.dns_upstream:
		commands += [
			"rm -rf /etc/resolv.conf",
			f"echo 'nameserver {str(upstream)}' >> /etc/resolv.conf",
		]
	
	allcommands += commands
	#output,error = execute_proxnode_commands(prox1, node, commands)

	# Wait for ping to function before continuing
	if not wait_for_container_ping_debian(prox1, container, 30):
		LOGGER.error(f"Container {node.hostname} cannot contact website")
		return
	
	#################################
	commands = commands_packages_essential(node)

	allcommands.append('######## commands_packages_essential #########')
	allcommands += commands
	#output,error = execute_proxnode_commands(prox1, node, commands)

	allcommands.append('######## upload assets #########')
	#paramiko_upload_pki_assets(node)

	#################################
	commands = commands_config_pki_1(node)

	allcommands.append('######## commands_config_pki_1 #########')
	allcommands += commands
	#output,error = execute_proxnode_commands(prox1, node, commands)

	# Wait for wildfly cli to function before continuing
	loop_no = 20
	delay = 5
	available = False
	LOGGER.debug('Attepting to connect to wildfly after restart.')
	while loop_no > 0:
		loop_no -= 1
		if paramiko_check_for_wildfly_cli(node):
			available = True
			break
		time.sleep(delay)

	if available == False:
		LOGGER.error(f'Error starting wildfly server on {node.hostname}.')
		return

	#################################
	commands = commands_config_pki_wildfly_cli(node)

	allcommands.append('######## commands_config_pki_wildfly_cli #########')
	allcommands += commands
	#output,error = execute_proxnode_commands(prox1, node, commands)

	# Wait for wildfly cli to function before continuing
	loop_no = 20
	delay = 5
	available = False
	LOGGER.debug('Attepting to connect to wildfly after restart.')
	while loop_no > 0:
		loop_no -= 1
		if paramiko_check_for_wildfly_cli(node):
			available = True
			break
		time.sleep(delay)

	if available == False:
		LOGGER.error(f'Error starting wildfly server on {node.hostname}.')
		return

	# region debug_notes TODO: It has been observed that there a wildfly cli failure due to 0.0.0.0:8443 being in use.
	# It can be resolved by manually running the command below again at this point.
	'''
	/opt/wildfly/bin/jboss-cli.sh --connect '/interface=management:write-attribute(name=inet-address, value=0.0.0.0)'
	/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/https-listener=httpspriv:add(socket-binding="httpspriv", ssl-context="httpspriv", max-parameters=2048)'
	systemctl stop wildfly
	sleep 4
	systemctl start wildflyc
	'''
	#endregion
	#################################
	commands = commands_config_pki_ejbca_install(node)

	allcommands.append('######## commands_config_pki_ejbca_install #########')
	allcommands += commands
	#output,error = execute_proxnode_commands(prox1, node, commands)

	# Wait for wildfly cli to function before continuing
	loop_no = 20
	delay = 5
	available = False
	LOGGER.debug('Attepting to connect to wildfly after restart.')
	while loop_no > 0:
		loop_no -= 1
		if paramiko_check_for_wildfly_cli(node):
			available = True
			break
		time.sleep(delay)

	if available == False:
		LOGGER.error(f'Error starting wildfly server on {node.hostname}.')
		return

	#################################
	commands = commands_config_pki_recreate_local_admin(node)

	allcommands.append('######## commands_config_pki_recreate_local_admin #########')
	allcommands += commands
	#output,error = execute_proxnode_commands(prox1, node, commands)

	paramiko_retrieve_local_cert(node)

	paramiko_retrieve_ejbca_cert(node, f'ca.{node.hostname}')

	generate_local_p12(node)

	with open(os.path.join(out_path,'all_commands.txt'), 'w') as f:
		for command in allcommands:
			if command.find(' | base64 -d | bash'):
				print (decode_all_base64_in_script(command), file=f)
				print('', file=f)
			else:
				print(command, file=f)
				print('', file=f)