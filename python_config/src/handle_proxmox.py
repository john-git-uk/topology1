from __future__ import annotations
from node import Node
import logging
import psutil
import re
import pexpect
import libvirt
import os
from interface import Interface
from topology import Topology
from pathlib import Path
import time
LOGGER = logging.getLogger('my_logger')
from proxmoxer import ProxmoxAPI
from pydantic import BaseModel
from typing import Optional, List
import paramiko
from project_globals import GLOBALS
import ipaddress
from requests.exceptions import ReadTimeout

class Container(BaseModel):
	ctid: int
	template: str
	memory: int=512
	swap: int=512
	cores: int=1
	rootfs: str
	resource_pool: str
	password: str="12345"
	disk_size: int=8
	node_data: Node

def test_validate_container_config(proxmox, container:  Container):
	if proxmox.machine_data.device_type != "proxmox":
		LOGGER.warning(f"Node {proxmox.hostname} is not a proxmox node!")
		return

	try:
		proxmox = ProxmoxAPI('your-proxmox-ip', user='root@pam', password='yourpassword', verify_ssl=False)
		
		config = proxmox.nodes(container.node_data.hostname).lxc(ctid).config.get()

		required_fields = {
			'hostname': str,
			'memory': int,
			'rootfs': str,
			'cores': int,
			'net0': str
		}

		LOGGER.debug("Not implemented.")

	except Exception as e:
		return False, f"Error retrieving or validating configuration: {e}"

def proxnode_reload_containers_service(proxmox, node, service_name):
	if node.get_machine_data.category != "debian":
		raise ValueError("Machine category is not debian")
	prox1 = ldap_server_1.topology_a_part_of.get_node("prox1")
	if not prox1:
		raise ValueError("Prox1 not found")
	for container in prox1.containers:
		if container.hostname == "ldap-server-1":
			my_container = container
			break
	if not my_container:
		raise ValueError("Container not found")
	
	ssh.connect(hostname=str(prox1.oob_interface.ipv4_address), username=prox1.local_user, password=prox1.local_password,port=22)

	if service_name == "ssh":
		stdin, stdout, stderr = ssh.exec_command(f"pct exec {my_container.ctid} -- systemctl restart ssh")
	if service_name == "ldap":
		stdin, stdout, stderr = ssh.exec_command(f"pct exec {my_container.ctid} -- systemctl restart slapd")
	if service_name == "slapd":
		stdin, stdout, stderr = ssh.exec_command(f"pct exec {my_container.ctid} -- systemctl restart slapd")
	if service_name == "radius":
		stdin, stdout, stderr = ssh.exec_command(f"pct exec {my_container.ctid} -- systemctl restart radiusd")
	
	ssh.close()

def execute_proxnode_commands(proxmox, node, commands, timeout = 120 ):
	if proxmox.machine_data.device_type != "proxmox":
		LOGGER.warning(f"Node {node.hostname} is not a proxmox node!")
		return
	my_container = None
	my_container = proxmox.get_container(node.hostname)
	if not my_container:
		raise ValueError("Container not found")
	
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(hostname=str(proxmox.oob_interface.ipv4_address), username=proxmox.local_user, password=proxmox.local_password,port=22)

	output = []
	error = []
	# Send the commands to file for review
	t_path = Path(GLOBALS.app_path).parent.resolve() / "output" / proxmox.hostname
	t_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(t_path,'proxnode_command_log.txt'), 'a') as f:
		for command in commands:
			if '"' in command:
				error_message = f"Command contains invalid double-quote character: {command}. Recommend using base64 encoding BEFORE sending for execution."
				LOGGER.error(error_message)
				raise ValueError(error_message)

			print(f'pct exec {my_container.ctid} -- sh -c "{command}"', file=f)
			LOGGER.debug("#### sending command: "+f'pct exec {my_container.ctid} -- sh -c "{command}"')
			stdin, stdout, stderr = ssh.exec_command(f'pct exec {my_container.ctid} -- sh -c "{command}"')
			
			start_time = time.time()

			while not stdout.channel.exit_status_ready():
				if time.time() - start_time > timeout:
					stdout.channel.close()
					stderr.channel.close()
					raise TimeoutError("Command timed out")
					return
			output += [stdout.read().decode()]
			error += [stderr.read().decode()]


	if (True): # Log terminal output?
		not_blank = []
		for line in output:
			if line:
				not_blank.append(line)
		if(len(not_blank) > 0):
			LOGGER.debug("### proxmox container stdout ###")
		for line in not_blank:
			if line:
				LOGGER.debug(line)

	not_blank = []
	for line in error:
		if line and line.strip() != "." and line != ".\n" and line != "+":
			not_blank.append(line)
	if (len(not_blank) > 0):
		LOGGER.warning("### proxmox container has stderr ###")
	for line in not_blank:
		if line:
			LOGGER.warning(line)
	ssh.close()

	return output, error

def start_container(proxmox, container, retries=30):
	if proxmox.machine_data.device_type != "proxmox":
		LOGGER.warning(f"Node {proxmox.hostname} is not a proxmox node!")
		return
	try:
		proxmoxapi = ProxmoxAPI(str(proxmox.oob_interface.ipv4_address), user='root@pam', password='toorp', verify_ssl=False)
	except Exception as e:
		LOGGER.error(f"Error connecting to Proxmox API: {e}")
		return None
	for attempt in range(retries):
		try:
			# Check the current container status
			status = proxmoxapi.nodes(proxmox.hostname).lxc(container.ctid).status.current.get()
			if status['status'] == 'running':
				LOGGER.debug(f"Container {container.ctid} is already running.")
				return status
				
			LOGGER.debug(f"Attempt {attempt + 1} to start container {container.ctid} on node {container.node_data.hostname}...")
			response = proxmoxapi.nodes(proxmox.hostname).lxc(container.ctid).status.start.post()
			LOGGER.debug(f"Container {container.ctid} started successfully.")
			return response
		except (ConnectionError, ReadTimeout) as e:
			LOGGER.debug(f"Network-related error: {e}")
		except Exception as e:
			LOGGER.debug(f"Failed to start container {container.ctid}: {e}")
			if attempt < retries - 1:
				LOGGER.debug(f"Retrying in 1 second... ({retries - attempt - 1} retries left)")
				time.sleep(1)
			else:
				LOGGER.error(f"All {retries} attempts failed to start container {container.ctid}.")

	return None

def test_create_container(proxmox, container:  Container):
	if proxmox.machine_data.device_type != "proxmox":
		LOGGER.warning(f"Node {proxmox.hostname} is not a proxmox node!")
		return
	if container.node_data is None:
		LOGGER.error(f"Container {container.ctid} does not have a node_data.")
		return
	else:
		node = container.node_data
	if node.get_identity_interface() is None:
		LOGGER.error(f"Node {node.hostname} could not provide an identity interface.")
		return
	else:
		identity_interface = node.get_identity_interface()
	if identity_interface.ipv4_address is None:
		LOGGER.error(f"Container {node.hostname} identity interface has no ipv4 address.")
		return
	if identity_interface.ipv4_cidr is None:
		LOGGER.error(f"Container {node.hostname} identity interface has no ipv4 cidr.")
		return
	
	proxmoxapi = ProxmoxAPI(str(proxmox.oob_interface.ipv4_address), user='root@pam', password='toorp', verify_ssl=False)

	for access in proxmox.topology_a_part_of.access_segments:
		for vlan in access.vlans:
			vlan_netid = ipaddress.IPv4Network(f'{vlan.ipv4_netid}/{vlan.ipv4_cidr}')
			if identity_interface.ipv4_address in vlan_netid:
				if vlan.default_gateway is None:
					if vlan.fhrp0_ipv4_address is None:
						LOGGER.error(f"VLAN {vlan.vlan_id} has neither a fhrp0_ipv4_address nor default gateway.")
						break
					else:
						default_gateway = vlan.fhrp0_ipv4_address
						break
				else:
					default_gateway = vlan.default_gateway
					break
				
	
	# Create netconfigs to pass as params
	net_configs = {}
	for idx in range (node.get_interface_count()):
		interface = node.get_interface_no(idx)
		if interface.ipv4_address is None:
			continue
		if interface.ipv4_cidr is None:
			continue
		if interface.neighbour is None:
			LOGGERER.warning(f"Interface {interface.name} on node {node.hostname} does not have a neighbour.")
			continue
		if interface.neighbour.name is None:
			LOGGERER.warning(f"Interface {interface.name} on node {node.hostname} has a neighbour without a name.")
			continue
		net_config = f"name={interface.name},bridge={interface.neighbour.name},ip={interface.ipv4_address}/{interface.ipv4_cidr}"
		if id(interface) == id(identity_interface):
			net_config += f",gw={default_gateway}"
		net_configs[f"net{idx}"] = net_config
	if len(net_configs) == 0:
		LOGGER.warning(f"No interfaces with IPv4 addresses found on node {node.hostname}.")

	params = {
		'vmid': container.ctid,
		'hostname': node.hostname,
		'ostemplate': container.template,
		'rootfs': container.rootfs,
		'memory': container.memory,
		'cores': container.cores,
		'swap': 512,
		'storage': 'local',
		'password': node.local_password,
		'timezone': 'host',
		'unprivileged': 1,
		'features': 'nesting=1'
	}
	params.update(net_configs)
	LOGGER.debug({**params})

	try:
		response = proxmoxapi.nodes(proxmox.hostname).lxc.create(**params)
	except Exception as e:
		LOGGER.error(f"Error creating container {node.hostname}: {e}")
		return
	LOGGER.info(f"Container {node.hostname} creation response: {response}")

def test_container_routes(proxmox, container: Container):
	if proxmox.machine_data.device_type != "proxmox":
		LOGGER.warning(f"Node {proxmox.hostname} is not a proxmox node!")
		return
	node = container.node_data
	topology = node.topology_a_part_of
	for interface in node.interfaces:
		if interface.ipv4_address is None:
			continue
		if interface.ipv4_cidr is None:
			continue
		if interface.neighbour is None:
			LOGGERER.warning(f"Interface {interface.name} on node {container.node_data.hostname} does not have a neighbour.")
			continue
		if interface.neighbour.ipv4_address is None:
			LOGGERER.warning(f"Interface {interface.name} on node {container.node_data.hostname} has a neighbour without a IPv4 address.")
			continue
		for acl in topology.access_controls:
			for vlan in acl.vlans:
				if interface.ipv4_address not in ipaddress.IPv4Network(f'{vlan.ipv4_netid}/{vlan.ipv4_cidr}'):
					continue
				my_vlan = vlan
				for tar_vlan in acl.vlans:
					directly_connected = False
					for interfacex in node.interfaces:
						if interfacex.ipv4_address not in ipaddress.IPv4Network(f'{vlan.ipv4_netid}/{vlan.ipv4_cidr}'):
							directly_connected = True
							break
					if not directly_connected:
						commands.append(f'ip route add {tar_vlan.ipv4_netid}/{tar_vlan.ipv4_cidr} via {my_vlan.default_gateway}')
				for tar_net in acl.allowlist:
					commands.append(f'ip route add {tar_net} via {interface.ipv4_address}')
						

		commands = [
			f"ip route add {interface.ipv4_address}/{interface.ipv4_cidr} via {interface.neighbour.ipv4_address}",
			f"ip route add default via {interface.neighbour.ipv4_address}"
		]
		execute_proxnode_commands(proxmox, container.node_data, commands)

def wait_for_container_running(proxmox, container: Container, retries=30):
	bootloop = 0
	while bootloop < retries:
		commands = ["pgrep -x init || pgrep -x systemd"]
		loop_output,loop_error = execute_proxnode_commands(proxmox, container.node_data, commands)
		# Check the result of the ping command
		if ''.join(loop_error).find("not running") == -1:
			break
		LOGGER.debug(f"waiting for {container.node_data.hostname} to boot up")
		bootloop += 1
		start_container(proxmox, container, 5)
		time.sleep(1)
	if bootloop == retries:
		LOGGER.error(f"#### {container.node_data.hostname} failed to boot up")
		return False
	return True

def wait_for_container_ping_debian(proxmox, container: Container, retries=30):
	if wait_for_container_running(proxmox, container, retries):
		loops = 0
		while loops < retries:
			commands = ["ping -c 1 -W 2 ftp.uk.debian.org"]
			loop_output,loop_error = execute_proxnode_commands(proxmox, container.node_data, commands)
			# Check the result of the ping command
			if not (''.join(loop_output).find("1 received") == -1):
				return True
			loops += 1

		LOGGER.error(f"#### {container.node_data.hostname} failed to ping ftp.uk.debian.org")
		return False
	else:
		return False