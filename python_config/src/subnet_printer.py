import ipaddress
import logging
LOGGER = logging.getLogger('my_logger')
from typing import List, Tuple
from convert import ipv4_netid
from topology import Topology
from project_globals import GLOBALS
import os
from pathlib import Path

class Printer_Subnet:
	def __init__(self, network: ipaddress.IPv4Network, descriptions=None):
		self.my_net_id = network
		self.descriptions = descriptions or []
		self.sub_subnets = []
		self.hosts = []
		
	def insert_network(self, insertion_netid: ipaddress.IPv4Network, description: str):
		"""
		Recursively insert a subnet into the tree under this node.
		"""
		# Check if the netid is a subsubnet of this one
		if insertion_netid.subnet_of(self.my_net_id):
			# Check if the netid is a subsubnet of an existing subsubnet
			for sub_subnet in self.sub_subnets:
				if insertion_netid.subnet_of(sub_subnet.my_net_id):
					# Recurse into the subsubnet
					sub_subnet.insert_network(insertion_netid, description)
					return
			# Check if duplicate of existing subsubnet
			for sub_subnet in self.sub_subnets:
				if insertion_netid == sub_subnet.my_net_id:
					sub_subnet.descriptions.append(description)
					return
			# If not subsubnet of our current subsubnet, insert as our subsubnet
			new_subnet = Printer_Subnet(insertion_netid, descriptions=[description])
			self.sub_subnets.append(new_subnet)
	
	def insert_host(self, ip: ipaddress.IPv4Address, cidr: int, description: str):
		# If its in my subnet
		if ip in (self.my_net_id):
			# If its cidr is smaller than my cidr
			if cidr > self.my_net_id.prefixlen:
				for sub_subnet in self.sub_subnets:
					# If its in one of my subsubnets recurse into it
					if ip in (sub_subnet.my_net_id):
						sub_subnet.insert_host(ip, cidr, description)
						return
				# The ip is in my subnet, but not a current subsubnet, and the prefix is not ours
				# Get the net id using a host address and cidr
				net_id = ipaddress.IPv4Network(f'{ipv4_netid(ip,cidr)}/{cidr}')
				self.insert_network(net_id, 'No Description')
				self.insert_host(ip,cidr,description)
			else:
				# If cidr is just wrong
				if cidr < self.my_net_id.prefixlen:
					LOGGER.error('Host address has prefix larger than subnet.')
					return
				self.hosts.append([(str)(ip),cidr,description])

	def output_tree(self, output, level=0):
		"""
		Output the network tree with indentation corresponding to the level.
		"""
		desc = ', '.join(self.descriptions) if self.descriptions else ''
		output.append((level, self.my_net_id, desc))
		# Sort subnet based on network address and prefix length
		for subnet in sorted(self.sub_subnets, key=lambda x: (int(x.my_net_id.network_address), x.my_net_id.prefixlen)):
			subnet.output_tree(output,level + 1)
		for host in self.hosts:
			output.append((level+1, f'{host[0]}/{host[1]}', str(host[2])))


def print_subnet_hierachy(subnet_list: List[Tuple[ipaddress.IPv4Network, str]], host_list: List[Tuple[ipaddress.IPv4Address, int, str]]):
	"""
	Organize a list of IPv4Network objects with descriptions into a hierarchical structure.
	"""

	# private IP ranges
	private_ip_ranges = [
		ipaddress.IPv4Network('10.0.0.0/8'),
		ipaddress.IPv4Network('172.16.0.0/12'),
		ipaddress.IPv4Network('192.168.0.0/16'),
	]
	# Create root nodes for top-level networks
	root_subnets = [Printer_Subnet(network) for network in private_ip_ranges]
	
	# Insert each network into the appropriate root node
	for network, description in subnet_list:
		inserted = False
		for root in root_subnets:
			if network.subnet_of(root.my_net_id):
				root.insert_network(network, description)
				inserted = True
				break
		if not inserted:
			# Network does not belong to any private IP range.
			LOGGER.error(f"Network {network} does not belong to any private IP range.")
	for host, cidr, description in host_list:
		host = (ipaddress.IPv4Address)(host)
		inserted = False
		for root in root_subnets:
			if host in root.my_net_id:
				root.insert_host(host, cidr, description)
				inserted = True
				break
		if not inserted:
			# Network does not belong to any private IP range.
			LOGGER.error(f"Host {host} does not belong to any private IP range.")
	output = {'networks': [], 'desciptions': []}
	
	output = []
	for root in root_subnets:
		root.output_tree(output)
	for indent, col1, col2 in output:
		print(indent*'   '+f'{col1} ---------- {col2}')
	
	out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "logs"
	out_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(out_path,'subnet_print.txt'), 'w') as f:
		for indent, col1, col2 in output:
			print(indent*'   '+f'{col1} ---------- {col2}', file=f)

def test_subnet_printer():
	# This data is fake and only for testing purposes.
	test_nets = [
		[ipaddress.IPv4Network('10.133.10.0/25'),'Sales Vlan'],
		[ipaddress.IPv4Network('10.133.20.0/23'),'Guest Vlan'],
		[ipaddress.IPv4Network('10.133.60.0/24'),'Guest-Services Vlan'],
	]
	test_hosts = [
		[ipaddress.IPv4Address('10.133.20.1'),23,'guest1'],
		[ipaddress.IPv4Address('10.133.20.2'),23,'guest2'],
		[ipaddress.IPv4Address('10.133.20.252'),23,'vlan-20.SW3'],
		[ipaddress.IPv4Address('10.133.20.253'),23,'vlan-20.SW4'],
		[ipaddress.IPv4Address('10.133.20.254'),23,'Guest Vlan HSRP'],
		[ipaddress.IPv4Address('10.133.21.252'),25,'vlan-10.SW3'],
		[ipaddress.IPv4Address('10.133.21.253'),25,'vlan-10.SW4'],
		[ipaddress.IPv4Address('10.133.21.254'),25,'sales Vlan HSRP'],
		[ipaddress.IPv4Address('10.133.10.1'),25,'sales1'],
		[ipaddress.IPv4Address('10.133.10.2'),25,'sales2'],
		[ipaddress.IPv4Address('10.133.10.3'),25,'sales3'],
		[ipaddress.IPv4Address('10.133.60.249'),24,'eth1.dns-server-1'],
		[ipaddress.IPv4Address('10.133.60.248'),24,'eth1.ldap-server-1'],
		[ipaddress.IPv4Address('10.133.60.247'),24,'eth1.radius-server-1'],

	]
	print_subnet_hierachy(test_nets, test_hosts)

def subnet_printer(topology: Topology):
	test_nets = []
	test_hosts = []

	for acc in topology.access_segments:
		for vlan in acc.vlans:
			test_nets.append([ipaddress.IPv4Network(f'{vlan.ipv4_netid}/{vlan.ipv4_cidr}'), str(f'{acc.name}: VLAN {vlan.name}')])
			if vlan.fhrp0_ipv4_address is not None:
				test_hosts.append([ipaddress.IPv4Address(vlan.fhrp0_ipv4_address),int(vlan.ipv4_cidr),str(f'{acc.name}: VLAN {vlan.name} FHRP address')])
			# TODO: DHCP pool?
	for node in topology.nodes:
		for interfacex in range(node.get_interface_count()):
			interface = node.get_interface_no(interfacex)
			if interface.ipv4_address == None:
				continue
			if node.machine_data.device_type == 'cisco_xe' or node.machine_data.device_type == 'cisco_ios':
				interface_name = f'{interface.interface_type} {interface.name}'
			else:
				interface_name = interface.name
			test_hosts.append([ipaddress.IPv4Address(interface.ipv4_address),int(interface.ipv4_cidr),str(f'Node {node.hostname} Interface {interface_name}')])
	print_subnet_hierachy(sorted(test_nets, key=lambda x: x[0]), sorted(test_hosts, key=lambda x: x[0]))