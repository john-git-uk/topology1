from __future__ import annotations
import random
import string
from convert import get_escaped_string, get_chunky_hex
import logging
LOGGER = logging.getLogger('my_logger')

def push_file_commands(node, dest_file, chmod, content):
	if node.machine_data.device_type != "debian":
		ValueError(f"Node {node.hostname} is not a debian node!")

	random_delimiter = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
	commands = [
		f"rm {dest_file}",
		f"touch {dest_file}",
		f"chmod {chmod} {dest_file}",
		f"cat <<EOF{random_delimiter} > {dest_file}\n{content}\nEOF{random_delimiter}",
	]
	return commands
def push_file_hex_commands(node, dest_file, chmod, content):
	if node.machine_data.device_type != "debian":
		ValueError(f"Node {node.hostname} is not a debian node!")
	
	commands = [
		f"rm {dest_file}",
		f"touch {dest_file}",
		f"chmod {chmod} {dest_file}",
	]
	chunky_hex = []
	chunky_hex = get_chunky_hex(content)
	LOGGER.debug(f"chunky_hex: {chunky_hex}")
	for chunk in chunky_hex:
		commands.append(f"echo -n '{chunk}' | xxd -r -p >> {dest_file}")
	return commands
	
def container_repo_reachability_check(container):
	if container is None:
		raise ValueError("handle_debian container_repo_reachability_check: passed container is None")
	if container.node_data is None:
		raise ValueError("handle_debian container_repo_reachability_check: passed node is None")
		node = container.node_data
	if node.topology_a_part_of is None:
		raise ValueError("handle_debian container_repo_reachability_check: passed node has no topology?")
	if node.machine_data.device_type != "debian":
		ValueError(f"Node {node.hostname} is not a debian node!")
	proxmox = None
	for find_proxmox in topology.nodes:
		if proxmox.machine_data.device_type == "proxmox":
			proxmox = find_proxmox
	if proxmox is None:
		raise ValueError(f"handle_debian container_repo_reachability_check: unable to find matching proxmox node for {node.hostname}")

	# Add reachability check for debian.org before running other commands
	print(f"Checking reachability of debian.org from container {my_container.ctid}")
	stdin, stdout, stderr = ssh.exec_command(f"pct exec {my_container.ctid} -- ping -c 4 debian.org")
	ping_output = stdout.read().decode()
	ping_error = stderr.read().decode()

	# Check the result of the ping command
	if "0% packet loss" in ping_output:
		print("#### debian.org is reachable!")
	else:
		print("#### debian.org is NOT reachable!")
		print(f"#### Ping Output: {ping_output}")
		print(f"#### Ping Error: {ping_error}")