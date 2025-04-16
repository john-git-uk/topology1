from __future__ import annotations
import random
import string
from convert import get_escaped_string, get_chunky_hex, get_chunky_base64, base64_encode_string, get_escaped_string
import logging
LOGGER = logging.getLogger('my_logger')
import requests
from pathlib import Path
from project_globals import GLOBALS
import subprocess
import time
import os
import re
import base64

def base64_encode_bash(bash):
	return f'echo {base64.b64encode(bash.encode()).decode()} | base64 -d | bash'

def base64_decode_bash(encoded_bash):
	"""
	Given a string of the form:
		"echo <BASE64_STRING> | base64 -d | bash"
	this function removes the 'echo ' prefix and the ' | base64 -d | bash'
	suffix, decodes the <BASE64_STRING>, and returns the original Bash command.

	Example:
		encoded_bash = "echo ZWNobyAiSGVsbG8i | base64 -d | bash"
		output       = "echo \"Hello\""

	Raises:
		ValueError: If the string doesn't match the expected pattern.
	"""
	prefix = 'echo' 
	suffix = ' | base64 -d | bash'
	
	# Ensure the string matches the expected pattern.
	if not (encoded_bash.startswith(prefix) and encoded_bash.endswith(suffix)):
		LOGGER.warning(
			"Decode base64 bash string does not match the pattern: 'echo <BASE64> | base64 -d | bash'"
		)
	
	# Extract just the Base64-encoded portion.
	base64_string = encoded_bash[len(prefix) : -len(suffix)]

	# Decode from Base64 to get the original Bash command.
	decoded_bytes = base64.b64decode(base64_string)
	return decoded_bytes.decode("utf-8")

def decode_all_base64_in_script(text):
	#region docstring
	"""
	Searches 'text' for all occurrences of the pattern:
		echo <BASE64_STRING> | base64 -d | bash

	1. Removes "echo " and " | base64 -d | bash".
	2. Decodes the <BASE64_STRING> from Base64.
	3. Replaces the entire 'echo <BASE64> | base64 -d | bash' substring
	with the decoded text.
	4. Preserves any other parts of 'text' that are not part of the pattern.

	Args:
		text (str): The input string that may contain zero or more 
					occurrences of the pattern.

	Returns:
		str: A new string with all matches replaced by their decoded content.
	"""
	#endregion

	#region regex explanation
	###########################
	#
	# echo\s+      matches 'echo' followed by one or more spaces
	# ([^ ]+)      captures one or more non-space characters (the Base64-encoded text)
	# \s+\|\s*     matches spaces, then a pipe '|', then maybe more spaces
	# base64\s+-d  matches 'base64 -d' with spaces
	# \s+\|\s*bash matches pipe '|', optional spaces, then 'bash'
	#
	#endregion

	pattern = r'echo\s+([^ ]+)\s+\|\s*base64\s+-d\s+\|\s*bash'

	def replace_func(match):
		# This group is the actual Base64 text
		b64_encoded = match.group(1)
		try:
			decoded_bytes = base64.b64decode(b64_encoded)
			decoded_str = decoded_bytes.decode('utf-8')
			return decoded_str
		except Exception as e:
			# If for some reason it fails to decode, keep the original match
			return match.group(0)

	# Use re.sub to replace all occurrences
	return re.sub(pattern, replace_func, text)

def push_file_commands(node, dest_file, chmod, content):
	#region docstring
	'''
	- Use base64 instead wherever possible -
	Reduces repeating bash commands for simple text file creation. This version does not
	encode therefore must be used carefully with quotes or other special characters.
	'''
	#endregion

	if node.machine_data.device_type != "debian":
		ValueError(f"Node {node.hostname} is not a debian node!")

	random_delimiter = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
	commands = [
		f"rm -f {dest_file}",
		f"touch {dest_file}",
		f"chmod {chmod} {dest_file}",
		f"cat <<EOF{random_delimiter} > {dest_file}\n{content}\nEOF{random_delimiter}",
	]
	return commands

def push_file_hex_commands(node, dest_file, chmod, content):
	#region docstring
	'''
	- Use base64 instead wherever possible -
	Reduces repeating bash commands for simple text file creation. This version	encodes 
	using hex therefore can be used with quotes or other special characters more liberaly.
	It requires xxd command on Linux to decode.
	'''
	#endregion
	if node.machine_data.device_type != "debian":
		ValueError(f"Node {node.hostname} is not a debian node!")
	
	commands = [
		(
			f"rm -f {dest_file}"
			+f"; touch {dest_file}"
			+f"; chmod {chmod} {dest_file}"
		),
	]

	chunky_hex = get_chunky_hex(content)
	LOGGER.debug(f"chunky_hex: {chunky_hex}")

	for chunk in chunky_hex:
		commands.append(f"echo -n '{chunk}' | xxd -r -p >> {dest_file}")

	return commands

def push_file_base64_commands(node, dest_file, chmod, content):
	#region docstring
	'''
	Reduces repeating bash commands for simple text file creation. This version	encodes 
	using base64 therefore can be used with quotes or other special characters more liberaly.
	Linux can likely decode without any package installation.
	'''
	#endregion

	# TODO: This function hasnt been tested!
	if node.machine_data.device_type != "debian":
		raise ValueError(f"Node {node.hostname} is not a debian node!")
	
	commands = [
		(
			f"rm -f {dest_file}"
			+ f"; touch {dest_file}"
			+ f"; chmod {chmod} {dest_file}"
		),
	]
	
	# Convert content to Base64 and split into chunks
	chunky_base64 = get_chunky_base64(content)
	LOGGER.debug(f"chunky_base64: {chunky_base64}")
	
	# Append commands to reconstruct the file using Base64 decoding
	for chunk in chunky_base64:
		commands.append(f"echo -n '{chunk}' | base64 -d >> {dest_file}")
	
	return commands

def container_repo_reachability_check(container):
	#region docstring
	'''
	This function tests if the given Linux container is able to reach ftp.uk.debian.org. This confirms that
	the majority of networking functions will be working.
	'''
	#endregion

	if container is None:
		LOGGER.error("handle_debian container_repo_reachability_check: passed container is None")
		return
	if container.node_data is None:
		LOGGER.error("handle_debian container_repo_reachability_check: passed node is None")
		return
	node = container.node_data
	if node.topology_a_part_of is None:
		LOGGER.error("handle_debian container_repo_reachability_check: passed node has no topology?")
		return
	if node.machine_data.device_type != "debian":
		LOGGER.error(f"Node {node.hostname} is not a debian node!")
		return
	proxmox = None
	for find_proxmox in topology.nodes:
		if proxmox.machine_data.device_type == "proxmox":
			proxmox = find_proxmox
	if proxmox is None:
		LOGGER.error(f"handle_debian container_repo_reachability_check: unable to find matching proxmox node for {node.hostname}")
		return

	# Add reachability check for debian.org before running other commands
	LOGGER.debug(f"Checking reachability of debian.org from container {my_container.ctid}")
	stdin, stdout, stderr = ssh.exec_command(f"pct exec {my_container.ctid} -- ping -c 4 ftp.uk.debian.org")
	ping_output = stdout.read().decode()
	ping_error = stderr.read().decode()

	# Check the result of the ping command
	if "0% packet loss" in ping_output:
		LOGGER.debug("#### debian packages are reachable.")
	else:
		LOGGER.error("#### debian packages are NOT reachable.")
		LOGGER.debug(f"#### Ping Output: {ping_output}")
		LOGGER.debug(f"#### Ping Error: {ping_error}")

def debian_interfaces(node):
	#region docstring
	'''
	This function provides commands for debian based systems for configuring interfaces
	that have been declared in the data structures.
	'''
	#endregion

	#TODO: This function is likely not tested sufficiantly.

	if node.machine_data.device_type != "debian" and node.machine_data.device_type != "proxmox":
		return
	node.interface_config_commands = []
	# Look for loopback interfaces and setup
	for index_a in range (node.get_interface_count()):
		interface = node.get_interface_no(index_a)
		if interface.interface_type != "loopback":
			continue
		if interface.search('.'):
			LOGGER.error(f"Loopback interface {interface.name} should not have a period in it's name")
			return
		node.interface_config_commands += [
			f'auto {interface.name}'
			f'iface {interface.name} inet static',
			f'    address {interface.ipv4_address}',
			f'    netmask {interface.ipv4_cidr}'
		]
	# Look for ethernet interfaces and setup
	for index_a in range (node.get_interface_count()):
		interface = node.get_interface_no(index_a)
		if interface.interface_type != "ethernet":
			continue
		if re.search(r'\.', interface.name):
			continue
		node.interface_config_commands += [
			f'auto {interface.name}'
		]
		if interface.ipv4_address:
			node.interface_config_commands += [
				f'iface {interface.name} inet static',
				f'    address {interface.ipv4_address}',
				f'    netmask {interface.ipv4_cidr}'
			]
		else:
			node.interface_config_commands += [
				f'iface {interface.name} inet manual',
			]
	# Look for subinterfaces and setup
	for index_a in range (node.get_interface_count()):
		interface = node.get_interface_no(index_a)
		if re.search(r'\.', interface.name) == None:
			continue
		node.interface_config_commands += [
			f'auto {interface.name}'
		]
		if interface.ipv4_address:
			LOGGER.error(f"Subinterface {interface.name} on {node.hostname} should not have an ip, use a bridge.")
			return
		else:
			node.interface_config_commands += [
				f'iface {interface.name} inet manual',
			]
	# Look for bridges and setup
	for index_a in range (node.get_interface_count()):
		interface = node.get_interface_no(index_a)
		if interface.interface_type != "bridge":
			continue
		if re.search(r'\.', interface.name):
			LOGGER.error(f"Bridge interface {interface.name} should not have a period in it's name")
			return
		node.interface_config_commands += [
			f'auto {interface.name}'
		]
		if interface.ipv4_address:
			node.interface_config_commands += [
				f'iface {interface.name} inet static',
				f'    address {interface.ipv4_address}',
				f'    netmask {interface.ipv4_cidr}',
				f'    bridge_ports {interface.neighbour.name}'
				f'    bridge_stp off'
				f'    bridge_fd 0'
			]
		else:
			LOGGER.error(f"Bridge interface {interface.name} should have an ipv4 address")
			return
		routes = []
		# For each of our vlans. TODO: trunk is l2, is this redundant?
		for vlan in interface.vlans:
			# Checking all the access controls
			for acc in topology.access_controls:
				# Checking all the vlans in access control
				for tar_vlan in acc.vlans:
					# Is our vlan a member of this access control?
					if id(vlan) != id(tar_vlan):
						continue
					# Static to every other member
					for dest_vlan in acc.vlans:
						in_list = False
						for route in routes:
							if route == f'{dest_vlan.ipv4_netid}/{dest_vlan.ipv4_cidr}':
								in_list = True
								break
						if not in_list:
							routes.append(f'{dest_vlan.ipv4_netid}/{dest_vlan.ipv4_cidr}')
				for allow in acc.allowlist:
					in_list = False
					for route in routes:
						if route == f'{allow.network_address}/{allow.prefixlen}':
							in_list = True
							break
					if not in_list:
						routes.append(f'{allow.network_address}/{allow.prefixlen}')
		for route in routes:
			node.interface_config_commands += [f'    post-up ip route add {route} dev {interface.name}']
		
	# Send the commands to file for review
	out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "interfaces"
	out_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(out_path,node.hostname+'_interfaces.txt'), 'w') as f:
		for command in node.interface_config_commands:
			print(command, file=f)

def commands_packages_essential(node):
	#region docstring
	'''
	This function returns commands for installing packages that are considered essential for this project.
	It also attempts to ensure locale is correct if not handled by proxmox.
	'''
	#endregion

	packages = [
		'xxd',
		'telnet',
		'curl',
		'openssh-client',
		'openssh-server',
		'nano',
		'iputils-ping',
		'build-essential',
		'net-tools',
		'iproute2',
		'rsyslog',
		'wget',
	]

	old_install_string = False
	if old_install_string:
		install_string = (
			'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends'
			+' xxd'
			+' telnet'
			+' curl'
			+' openssh-client'
			+' openssh-server'
			+' nano'
			+' iputils-ping'
			+' build-essential'
			+' net-tools'
			+' iproute2'
			+' rsyslog'
			+' wget'
			+' < /dev/null > build_essential.log 2>&1'
		)
	else:
		pass

	commands = [
		f'echo {base64_encode_string('--- build-essential packages begins ---')} | base64 -d > build_essential.log',
		'apt-get update',
		'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends locales < /dev/null >> build_essential.log 2>&1',
	]
	commands.append
	(
		"sed -i '/en_GB.UTF-8/s/^# //g' /etc/locale.gen"
		+'; locale-gen en_GB.UTF-8'
		+'; update-locale LANG=en_GB.UTF-8 LC_ALL=en_GB.UTF-8'
		+"; echo 'LANG=\"en_GB.UTF-8\"' > /etc/default/locale"
		+"; echo 'LC_ALL=\"en_GB.UTF-8\"' >> /etc/default/locale"
		+ " 2>&1 | tee -a /var/log/locale-setup.log",
		'apt-get upgrade -y < /dev/null >> build_essential.log 2>&1'
	)

	# Due to the amount of time it takes it is better not to combine packages. This increases overhead
	# however it makes it easier to debug and reduces the chances of unnecessary timeouts.
	combined = False
	if combined:
		install_string = 'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends'
		for package in packages:
			install_string += ' ' +package
		install_string += ' < /dev/null > build_essential.log 2>&1'

		commands.append(install_string)
	else: # combined == False
		for package in packages:
			commands.append(f'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {package} < /dev/null > build_essential.log 2>&1')

	commands += (push_file_hex_commands(node, "/etc/ssh/sshd_config", "644", debian_sshd_content(node)))
	commands.append('systemctl restart ssh')
	return commands

def debian_sshd_content(node):
	#region return string
	return f"""
SyslogFacility AUTH
LogLevel VERBOSE
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ListenAddress {node.oob_interface.ipv4_address}
"""
	#endregion
