
from __future__ import annotations
from topology import Topology
from handle_vmm import test_interact_vmm
#from node_data.node_ISP_data import ISP_Structures, ISP_relations
from node_data.node_r1_data import r1_Structures, r1_relations
from node_data.node_r2_data import r2_Structures, r2_relations
from node_data.node_r3_data import r3_Structures, r3_relations
from node_data.node_sw1_data import sw1_Structures, sw1_relations
from node_data.node_sw2_data import sw2_Structures, sw2_relations
from node_data.node_sw3_data import sw3_Structures, sw3_relations
from node_data.node_sw4_data import sw4_Structures, sw4_relations
from node_data.node_sw5_data import sw5_Structures, sw5_relations
from node_data.node_sw6_data import sw6_Structures, sw6_relations
from node_data.node_sw7_data import sw7_Structures, sw7_relations
from node_data.node_prox1_data import prox1_structures, prox1_relations
from node_data.node_ldap_server_1 import ldap_server_1_structures, ldap_server_1_relations
from node_data.node_radius_server_1 import radius_server_1_structures, radius_server_1_relations
from node_data.node_dns_server_1 import dns_server_1_structures, dns_server_1_relations
from node_data.node_ca_server_1 import ca_server_1_structures, ca_server_1_relations
from project_globals import GLOBALS
from paramiko import SSHClient
from paramiko import Transport#, RSAKey
import logging
import time
import sys
import os
from pathlib import Path
import libvirt
import subprocess
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
		LOGGER.info("Connecting to r3")

		# Manually create the transport with custom Kex and MAC algorithms
		transport = Transport((str(topology.get_node("r3").oob_interface.ipv4_address), 22))
		transport.get_security_options().kex = ['diffie-hellman-group-exchange-sha1']
		transport.get_security_options().ciphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr']

		# Set up the connection using transport
		transport.connect(username=topology.get_node("r3").local_user, password=topology.get_node("r3").local_password)

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
	r1_Structures(topology)
	LOGGER.debug("r1 Structures loaded")
	r2_Structures(topology)
	LOGGER.debug("r2 Structures loaded")
	r3_Structures(topology)
	LOGGER.debug("r3 Structures loaded")
	sw1_Structures(topology)
	LOGGER.debug("sw1 Structures loaded")
	sw2_Structures(topology)
	LOGGER.debug("sw2 Structures loaded")
	sw3_Structures(topology)
	LOGGER.debug("sw3 Structures loaded")
	sw4_Structures(topology)
	LOGGER.debug("sw4 Structures loaded")
	sw5_Structures(topology)
	LOGGER.debug("sw5 Structures loaded")
	sw6_Structures(topology)
	LOGGER.debug("sw6 Structures loaded")
	sw7_Structures(topology)
	LOGGER.debug("sw7 Structures loaded")
	prox1_structures(topology)
	LOGGER.debug("Prox1 Structures loaded")
	ldap_server_1_structures(topology)
	LOGGER.debug("LDAP Server 1 Structures loaded")
	radius_server_1_structures(topology)
	LOGGER.debug("Radius Server 1 Structures loaded")
	dns_server_1_structures(topology)
	LOGGER.debug("DNS Server 1 Structures loaded")
	ca_server_1_structures(topology)
	LOGGER.debug("CA Server 1 Structures loaded")

	main_relations(topology)
	LOGGER.debug("Main Relations loaded")
	#ISP_relations(topology)
	#LOGGER.debug("ISP Relations loaded")
	r1_relations(topology)
	LOGGER.debug("r1 Relations loaded")
	r2_relations(topology)
	LOGGER.debug("r2 Relations loaded")
	r3_relations(topology)
	LOGGER.debug("r3 Relations loaded")
	sw1_relations(topology)
	LOGGER.debug("sw1 Relations loaded")
	sw2_relations(topology)
	LOGGER.debug("sw2 Relations loaded")
	sw3_relations(topology)
	LOGGER.debug("sw3 Relations loaded")
	sw4_relations(topology)
	LOGGER.debug("sw4 Relations loaded")
	sw5_relations(topology)
	LOGGER.debug("sw5 Relations loaded")
	sw6_relations(topology)
	LOGGER.debug("sw6 Relations loaded")
	sw7_relations(topology)
	LOGGER.debug("sw7 Relations loaded")
	prox1_relations(topology)
	LOGGER.debug("Prox1 Relations loaded")
	ldap_server_1_relations(topology)
	LOGGER.debug("LDAP Server 1 Relations loaded")
	radius_server_1_relations(topology)
	LOGGER.debug("Radius Server 1 Relations loaded")
	dns_server_1_relations(topology)
	LOGGER.debug("DNS Server 1 Relations loaded")
	ca_server_1_relations(topology)
	LOGGER.debug("CA Server 1 Relations loaded")

	return topology

def simple_function_prompt(topology:  Topology):
	#create list of functions to run

	# Make sure these remain in sync...
	functions_display = [
		"Globals: Validate Data",#1
		"Globals: Load Data",#2
		"Run Worker in main thread",#3
		"SSH: Validate Interfaces Exist",#4
		"Print a subnet tree for the topology",#5
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
	#try:
	if True:
		selected_function_index = int(input_str)
		if 1 <= selected_function_index <= len(functions_display):
			if(selected_function_index == 1):
				GLOBALS.validate_data()
			elif(selected_function_index == 2):
				GLOBALS.load_data()
			elif(selected_function_index == 3):
				run_worker_main_prompt(topology)
				#subprocess.Popen([sys.executable, __file__, "worker", "dns-server-1"])
				#subprocess.Popen([sys.executable, __file__, "worker", "ldap-server-1"])
				#subprocess.Popen([sys.executable, __file__, "worker", "radius-server-1"])
			elif(selected_function_index == 4):
				for node in topology.nodes:
					LOGGER.debug(f"Validating interfaces for {node.hostname}")
					node.cisco_validate_layer_1_genie()
			elif(selected_function_index == 5):
				from subnet_printer import subnet_printer
				subnet_printer(topology)
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
	#except ValueError as e:
	#	LOGGER.warning(f"Function selector: Invalid input. Enter a valid number. {e}")

def run_worker_main_prompt(topology: Topology):
	functions_display = [
		"dns-server-1",#1
		"ldap-server-1",#2
		"radius-server-1",#3
		"test: CA CONFIG",#4
		"klo",#5
		"klo",#6
		"klo",#7
		"klo",#8
		"klo",#9
	]

	# Print the list of functions with their names and index
	for index, function_name in enumerate(functions_display, start=1):
		print(f"{index}. {function_name}")
	input_str = input("Enter the number of the function to run: ")
	selected_function_index = int(input_str)
	if 1 <= selected_function_index <= len(functions_display):
		if(selected_function_index == 1):
			start_worker(topology, 'dns-server-1')
		elif(selected_function_index == 2):
			start_worker(topology, 'ldap-server-1')
		elif(selected_function_index == 3):
			start_worker(topology, 'radius-server-1')
		elif(selected_function_index == 4):
			start_worker(topology, 'ca-server-1')
		elif(selected_function_index == 5):
			pass
		elif(selected_function_index == 6):
			pass
		elif(selected_function_index == 7):
			pass
		elif(selected_function_index == 8):
			pass
		elif(selected_function_index == 9):
			pass
		else:
			LOGGER.warning("Function selector: Invalid input. Enter a valid number.")
	else:
		LOGGER.warning("Function selector: Invalid input. Enter a valid number.")

def start_worker(topology: Topology, type: str):
	from handle_proxmox import Container, test_create_container, test_validate_container_config, start_container
	from node_data.node_dns_server_1 import dns_server_1_config
	from node_data.node_ldap_server_1 import ldap_server_1_config
	from node_data.node_radius_server_1 import radius_server_1_config
	from node_data.node_ca_server_1 import ca_server_1_config
	if type == 'dns-server-1':
		node = topology.get_node('dns-server-1')
		test_create_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("dns-server-1"))
		dns_server_1_config(node)
		
	elif type == 'ldap-server-1':
		node = topology.get_node("ldap-server-1")
		test_create_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("ldap-server-1"))
		ldap_server_1_config(topology.get_node("ldap-server-1"))

	elif type == 'radius-server-1':
		node = topology.get_node("radius-server-1")
		test_create_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("radius-server-1"))
		radius_server_1_config(topology.get_node("radius-server-1"))
	
	elif type == 'ca-server-1':
		node = topology.get_node("ca-server-1")
		test_create_container(topology.get_node("prox1"),topology.get_node("prox1").get_container("ca-server-1"))
		ca_server_1_config(topology.get_node("ca-server-1"))
	else:
		LOGGER.error(f'Unknown worker type: {type}')
		return

def pre_main_testing():
	from convert import base64_encode_string
	log_file = Path.joinpath(GLOBALS.app_path.parent,'output','testing.log')
	commands = []

	commands.append(f'echo {base64_encode_string('"double quotes"')}{base64_encode_string("'single quotes'")} | base64 -d > {log_file}')
	commands.append(f'cat {log_file}')
	for command in commands:
		print(command)
		try:
			result = subprocess.check_output(command, shell = True, executable = "/bin/bash", stderr = subprocess.STDOUT)

		except subprocess.CalledProcessError as cpe:
			result = cpe.output

		finally:
			for line in result.splitlines():
				print(line.decode())

def main():
	pre_main_testing()
	first_arg = None
	second_arg = None
	if len(sys.argv) > 1:
		first_arg = sys.argv[1]
		if len(sys.argv) > 2:
			second_arg = sys.argv[2]
	print("Printing DEBUG severity messages to the terminal")
	# Create logger
	LOGGER.setLevel(logging.DEBUG)  # Set the minimum logging level

	# Create handlers
	stream_handler = logging.StreamHandler()  # Logs to terminal (stdout)
	out_path = Path(GLOBALS.app_path).parent.resolve() / "output/logs"
	out_path.mkdir(exist_ok=True, parents=True)
	if(first_arg != 'worker'):
		file_handler = logging.FileHandler(os.path.join(os.path.abspath(out_path),'main.log'))  # Logs to file
	else:
		file_handler = logging.FileHandler(os.path.join(os.path.abspath(out_path),F'worker {str(second_arg)}.log' ))  # Logs to file

	# Create formatters and add it to handlers
	formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
	stream_handler.setFormatter(formatter)
	file_handler.setFormatter(formatter)

	# Add handlers to the logger
	if(first_arg != 'worker'):
		LOGGER.addHandler(stream_handler)
	LOGGER.addHandler(file_handler)

	GLOBALS.load_data()
	topology = load_topology()
	LOGGER.info("Topology Data loaded")

	if(first_arg != 'worker'):
		while True:
			time.sleep(1)
			simple_function_prompt(topology)
	else:
		start_worker(topology, second_arg)
		LOGGER.info("Worker completed. Terminating...")
		sys.exit(0)
main()