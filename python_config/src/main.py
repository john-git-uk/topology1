
from __future__ import annotations
from topology import Topology
from handle_vmm import test_interact_vmm
#from node_data.node_ISP_data import ISP_Structures, ISP_relations
from node_data.node_R1_data import R1_Structures, R1_relations
from node_data.node_R2_data import R2_Structures, R2_relations
from node_data.node_R3_data import R3_Structures, R3_relations
from node_data.node_SW1_data import SW1_Structures, SW1_relations
from node_data.node_SW2_data import SW2_Structures, SW2_relations
from node_data.node_SW3_data import SW3_Structures, SW3_relations
from node_data.node_SW4_data import SW4_Structures, SW4_relations
from node_data.node_SW5_data import SW5_Structures, SW5_relations
from node_data.node_SW6_data import SW6_Structures, SW6_relations
from node_data.node_SW7_data import SW7_Structures, SW7_relations
from node_data.node_prox1_data import prox1_structures, prox1_relations
from node_data.node_ldap_server_1 import ldap_server_1_structures, ldap_server_1_relations
from node_data.node_radius_server_1 import radius_server_1_structures, radius_server_1_relations
from node_data.node_dns_server_1 import dns_server_1_structures, dns_server_1_relations
from project_globals import GLOBALS
from paramiko import SSHClient
from paramiko import Transport#, RSAKey
import logging
import time
import sys
import os
from pathlib import Path
import libvirt
VIR_DOMAIN_STATE_LOOKUP = {
	libvirt.VIR_DOMAIN_NOSTATE: 'No State',
	libvirt.VIR_DOMAIN_RUNNING: 'Running',
	libvirt.VIR_DOMAIN_BLOCKED: 'Blocked',
	libvirt.VIR_DOMAIN_PAUSED: 'Paused',
	libvirt.VIR_DOMAIN_SHUTDOWN: 'Shutting Down',
	libvirt.VIR_DOMAIN_SHUTOFF: 'Shut Off',
	libvirt.VIR_DOMAIN_CRASHED: 'Crashed',
	libvirt.VIR_DOMAIN_PMSUSPENDED: 'Power Management Suspended',
}
LOGGER = logging.getLogger('my_logger')

sys.setrecursionlimit(30111)  # Set a lower recursion limit

def test_connect_with_custom_ssh(topology: Topology):
	try:
		LOGGER.info("Connecting to R3")

		# Manually create the transport with custom Kex and MAC algorithms
		transport = Transport((str(topology.get_node("R3").oob_interface.ipv4_address), 22))
		transport.get_security_options().kex = ['diffie-hellman-group-exchange-sha1']
		transport.get_security_options().ciphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr']

		# Set up the connection using transport
		transport.connect(username=topology.get_node("R3").local_user, password=topology.get_node("R3").local_password)

		ssh = SSHClient()
		ssh._transport = transport

		# Example: running a command
		stdin, stdout, stderr = ssh.exec_command("show version")
		print(stdout.read().decode())

		ssh.close()
	except Exception as e:
		LOGGER.error("An error occurred: %s", str(e))
def load_topology():
	from topology_data import main_structures, main_relations
	from node import Node
	from vlan import VLAN
	from access_segment import AccessSegment
	from interface import Interface

	#VLAN.update_forward_refs()
	#Interface.update_forward_refs()
	#Node.update_forward_refs()
	#Topology.update_forward_refs()
	Topology.model_rebuild()
	
	topology = Topology()
	main_structures(topology)
	LOGGER.debug("Topology main loaded")
	#ISP_Structures(topology)
	#LOGGER.debug("ISP Structures loaded")
	R1_Structures(topology)
	LOGGER.debug("R1 Structures loaded")
	R2_Structures(topology)
	LOGGER.debug("R2 Structures loaded")
	R3_Structures(topology)
	LOGGER.debug("R3 Structures loaded")
	SW1_Structures(topology)
	LOGGER.debug("SW1 Structures loaded")
	SW2_Structures(topology)
	LOGGER.debug("SW2 Structures loaded")
	SW3_Structures(topology)
	LOGGER.debug("SW3 Structures loaded")
	SW4_Structures(topology)
	LOGGER.debug("SW4 Structures loaded")
	SW5_Structures(topology)
	LOGGER.debug("SW5 Structures loaded")
	SW6_Structures(topology)
	LOGGER.debug("SW6 Structures loaded")
	SW7_Structures(topology)
	LOGGER.debug("SW7 Structures loaded")
	prox1_structures(topology)
	LOGGER.debug("Prox1 Structures loaded")
	ldap_server_1_structures(topology)
	LOGGER.debug("LDAP Server 1 Structures loaded")
	radius_server_1_structures(topology)
	LOGGER.debug("Radius Server 1 Structures loaded")
	dns_server_1_structures(topology)
	LOGGER.debug("DNS Server 1 Structures loaded")

	main_relations(topology)
	LOGGER.debug("Main Relations loaded")
	#ISP_relations(topology)
	#LOGGER.debug("ISP Relations loaded")
	R1_relations(topology)
	LOGGER.debug("R1 Relations loaded")
	R2_relations(topology)
	LOGGER.debug("R2 Relations loaded")
	R3_relations(topology)
	LOGGER.debug("R3 Relations loaded")
	SW1_relations(topology)
	LOGGER.debug("SW1 Relations loaded")
	SW2_relations(topology)
	LOGGER.debug("SW2 Relations loaded")
	SW3_relations(topology)
	LOGGER.debug("SW3 Relations loaded")
	SW4_relations(topology)
	LOGGER.debug("SW4 Relations loaded")
	SW5_relations(topology)
	LOGGER.debug("SW5 Relations loaded")
	SW6_relations(topology)
	LOGGER.debug("SW6 Relations loaded")
	SW7_relations(topology)
	LOGGER.debug("SW7 Relations loaded")
	prox1_relations(topology)
	LOGGER.debug("Prox1 Relations loaded")
	ldap_server_1_relations(topology)
	LOGGER.debug("LDAP Server 1 Relations loaded")
	radius_server_1_relations(topology)
	LOGGER.debug("Radius Server 1 Relations loaded")
	dns_server_1_relations(topology)
	LOGGER.debug("DNS Server 1 Relations loaded")


	return topology
def simple_function_prompt(topology:  Topology):
	#create list of functions to run

	# Make sure these remain in sync...
	functions_display = [
		"Globals: Validate Data",#1
		"Globals: Load Data",#2
		"Configure prox1 containers",#3
		"SSH: Validate Interfaces Exist",#4
		"Unused",#5
		"Topology: Generate Multiple Config for Cisco Nodes",#6
		"Lab Handler: Import Virtual Console Telnet Ports from Lab API",#7
		"Topology: Copy Config Files to a Linux Node",#8
		"Test: Interact with VMM",#9
	]

	# Print the list of functions with their names and index
	for index, function_name in enumerate(functions_display, start=1):
		print(f"{index}. {function_name}")
	input_str = input("Enter the number of the function to run: ")
	# check input and run the function
	try:
		selected_function_index = int(input_str)
		if 1 <= selected_function_index <= len(functions_display):
			if(selected_function_index == 1):
				GLOBALS.validate_data()
			elif(selected_function_index == 2):
				GLOBALS.load_data()
			elif(selected_function_index == 3):
				from handle_proxmox import Container, test_create_container, test_validate_container_config, start_container
				test_create_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("ldap-server-1"))
				test_create_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("radius-server-1"))
				test_create_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("dns-server-1"))
				start_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("ldap-server-1"))
				start_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("radius-server-1"))
				start_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("dns-server-1"))

				from node_data.node_ldap_server_1 import configure_ldap_server_1, packages_time_ldap_server_1
				from node_data.node_radius_server_1 import configure_radius_server_1, packages_time_radius_server_1
				from node_data.node_dns_server_1 import configure_dns_server_1, packages_time_dns_server_1

				packages_time_dns_server_1(topology.get_node("dns-server-1"))
				configure_dns_server_1(topology.get_node("dns-server-1"))
				packages_time_ldap_server_1(topology.get_node("ldap-server-1"))
				configure_ldap_server_1(topology.get_node("ldap-server-1"))
				packages_time_radius_server_1(topology.get_node("radius-server-1"))
				configure_radius_server_1(topology.get_node("radius-server-1"))
			elif(selected_function_index == 4):
				for node in topology.nodes:
					LOGGER.debug(f"Validating interfaces for {node.hostname}")
					node.validate_interfaces_genie()
			elif(selected_function_index == 5):
				pass
			elif(selected_function_index == 6):
				topology.generate_multi_config()
			elif(selected_function_index == 7):
				if(os.path.exists("../python_config/src/handle_lab.py")):
					from handle_lab import test_import_vconsole_telnet
					LOGGER.debug("Handle lab script found, attemtping to import telnet ports.")
					test_import_vconsole_telnet(topology)
				else:
					LOGGER.warning("Handle lab script not found. Skipping...")
					LOGGER.info("You can enter the correct telnet ports manually in the topology file.")
			elif(selected_function_index == 8):
				topology.choose_linux_node_for_telnet_config()
			elif(selected_function_index == 9):
				test_interact_vmm(topology)
			else:
				LOGGER.warning("Function selector: Invalid input. Enter a valid number.")
		else:
			LOGGER.warning("Function selector: Invalid input. Enter a valid number.")
	except ValueError:
		LOGGER.warning("Function selector: Invalid input. Enter a valid number.")
def main():
	print("Printing DEBUG severity messages to the terminal")
	# Create logger
	LOGGER.setLevel(logging.DEBUG)  # Set the minimum logging level

	# Create handlers
	stream_handler = logging.StreamHandler()  # Logs to terminal (stdout)
	out_path = Path(GLOBALS.app_path).parent.resolve() / "output/logs"
	out_path.mkdir(exist_ok=True, parents=True)
	file_handler = logging.FileHandler(os.path.join(os.path.abspath(out_path),'main.log'))  # Logs to file

	# Create formatters and add it to handlers
	formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
	stream_handler.setFormatter(formatter)
	file_handler.setFormatter(formatter)

	# Add handlers to the logger
	LOGGER.addHandler(stream_handler)
	LOGGER.addHandler(file_handler)

	GLOBALS.load_data()
	topology = load_topology()
	LOGGER.info("Topology Data loaded")
	while True:
		time.sleep(1)
		simple_function_prompt(topology)
main()