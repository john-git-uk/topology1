from project_globals import *
from topology_data import *
import logging
import pexpect
import sys
import psutil
import re
import json,time,urllib
from tabulate import tabulate
import os
from pathlib import Path
import configparser
from scp import SCPClient
from dotenv import load_dotenv
import requests
import importlib.util
import libvirt
LOGGER = logging.getLogger('my_logger')
def generate_nodes_interfaces_config(topology: "Topology"):
	try:
		LOGGER.info("Generating interfaces config for all nodes")
		LOGGER.debug(f"Here are the nodes in the list: {topology.nodes}")
		for node in topology.nodes:
			LOGGER.debug(f"Considering generating interfaces config for node: {node.hostname}")
			node.generate_interfaces_config()
			LOGGER.debug(f"Considering apply config for node using netmiko: {node.hostname}")
			if(node.machine_data.device_type != "cisco_ios" and node.machine_data.device_type != "cisco_xe"):
				continue
			node.apply_interfaces_config_netmiko()
	except Exception as e:
		LOGGER.error(f"Error generating interfaces config for all nodes: {e}")
		raise
def generate_nodes_ssh_stubs(topology: "Topology"):
	try:
		LOGGER.info("Generating ssh stubs for all nodes")
		LOGGER.debug(f"Here are the nodes in the list: {topology.nodes}")
		for node in topology.nodes:
			LOGGER.debug(f"Considering generating ssh stubs for node: {node.hostname}")
			node.generate_ssh_stub()
	except Exception as e:
		LOGGER.error(f"Error generating ssh stubs for all nodes: {e}")
		raise
def choose_linux_node_for_telnet_config(topology: "Topology"):
	shortlist = []
	for node in topology.nodes:
		if node.machine_data.device_type == "debian" or node.machine_data.device_type == "ubuntu" or node.machine_data.device_type == "alpine":
			shortlist.append(node)
	for index, node in enumerate(shortlist, start=1):
		print(f"{index}. {node.hostname}")
	while True:
		selection = input("Pick a node to configure using telnet:")
		# If selection matches the index of a node exit the loop
		if(selection.isdigit() and 1 <= int(selection) <= len(shortlist)):
			selected_node = shortlist[int(selection) - 1]
			selected_node.config_using_telnet_vconsole()
			break
		else:
			print("Invalid selection.")	
	return None