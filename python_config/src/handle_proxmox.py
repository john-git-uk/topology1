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

def execute_proxnode_commands(proxmox, node, commands):
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
			print(f'pct exec {my_container.ctid} -- sh -c "{command}"', file=f)
			LOGGER.debug("#### sending command: "+f'pct exec {my_container.ctid} -- sh -c "{command}"')
			stdin, stdout, stderr = ssh.exec_command(f'pct exec {my_container.ctid} -- sh -c "{command}"')
			output += [stdout.read().decode()]
			error += [stderr.read().decode()]
	LOGGER.debug("######################## output ########################")
	for line in output:
		if line:
			LOGGER.debug(line)
	LOGGER.debug("######################## error ########################")
	for line in error:
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

	proxmoxapi = ProxmoxAPI(str(proxmox.oob_interface.ipv4_address), user='root@pam', password='toorp', verify_ssl=False)

	interface_eth0 = container.node_data.get_interface("ethernet","eth0")
	interface_eth1 = container.node_data.get_interface("ethernet","eth1")
	if(interface_eth0.ipv4_address is None):
		raise ValueError(f"Interface eth0 on node {container.node_data.hostname} is not configured and is required for test function")
	if(interface_eth1.ipv4_address is None):
		raise ValueError(f"Interface eth1 on node {container.node_data.hostname} is not configured and is required for test function")

	for access in proxmox.topology_a_part_of.access_segments:
		if access.name == "main":
			for vlan in access.vlans:
				if vlan.name == "guest-services": # TODO: this should not be hardcoded
					default_gateway = vlan.fhrp0_ipv4_address
	net_config=f"name={interface_eth0.name},bridge={interface_eth0.neighbour.name},ip={interface_eth0.ipv4_address}/{interface_eth0.ipv4_cidr}"
	net_config2=f"name={interface_eth1.name},bridge={interface_eth1.neighbour.name},ip={interface_eth1.ipv4_address}/{interface_eth1.ipv4_cidr},gw={default_gateway}"
	
	LOGGER.debug([
		"vmid=",container.ctid,
		"hostname=",container.node_data.hostname,
		"ostemplate=",container.template,
		"rootfs=",container.rootfs,
		"memory=",container.memory,
		"cores=",container.cores,
		"net0=",net_config,
		"net1=",net_config2,
		"swap=",512,
		"storage=",'local',
		"password=",container.node_data.local_password,
		"timezone=",'host',
		"unprivileged=",1 
	])
	try:
		response = proxmoxapi.nodes(proxmox.hostname).lxc.create(
			vmid=container.ctid,
			hostname=container.node_data.hostname,
			ostemplate=container.template,
			rootfs=container.rootfs,
			memory=container.memory,
			cores=container.cores,
			net0=net_config,
			net1=net_config2,
			swap=512,
			storage='local',
			password=container.node_data.local_password,
			timezone='host',
			unprivileged=1,
			features='nesting=1'
		)
	except Exception as e:
		LOGGER.error(f"Error creating container {container.node_data.hostname}: {e}")
		return
	LOGGER.info(f"Container {container.node_data.hostname} creation response: {response}")

def prox1_relations(prox1: Node):
	ldap_server_1 = None
	radius_server_1 = None
	dns_server_1 = None
	for container in prox1.containers:
		if container.node_data.hostname == "ldap-server-1":
			ldap_server_1 = container.node_data
		if container.node_data.hostname == "radius-server-1":
			radius_server_1 = container.node_data
		if container.node_data.hostname == "dns-server-1":
			dns_server_1 = container.node_data
	
	if(ldap_server_1 is None):
		raise Exception("ldap_server_1 is None")
	if(radius_server_1 is None):
		raise Exception("radius_server_1 is None")
	if(dns_server_1 is None):
		raise Exception("dns_server_1 is None")

	ldap_server_1.get_interface("eth0").connect_to(prox1.get_interface("bridge","oob_hitch"))
	ldap_server_1.get_interface("eth1").connect_to(prox1.get_interface("bridge","vmbr60"))
	radius_server_1.get_interface("eth0").connect_to(prox1.get_interface("bridge","oob_hitch"))
	radius_server_1.get_interface("eth1").connect_to(prox1.get_interface("bridge","vmbr60"))
	dns_server_1.get_interface("eth0").connect_to(prox1.get_interface("bridge","oob_hitch"))
	dns_server_1.get_interface("eth1").connect_to(prox1.get_interface("bridge","vmbr60"))

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
			commands = ["ping -c 1 -W 2 debian.org"]
			loop_output,loop_error = execute_proxnode_commands(proxmox, container.node_data, commands)
			# Check the result of the ping command
			if not (''.join(loop_output).find("1 received") == -1):
				return True
			loops += 1

		LOGGER.error(f"#### {container.node_data.hostname} failed to ping debian.org")
		return False
	else:
		return False