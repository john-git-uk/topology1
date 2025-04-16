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
from handle_debian.handle_debian import push_file_base64_commands, push_file_hex_commands

def commands_packages_radius_server(node):
	#region docstring
	'''
	Provides commands for Debian based systems for installing the packages required for providing RADIUS services.
	'''
	#endregion
	install_string = (
		'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends' 
		+' freeradius'
		+' freeradius-utils'
		+' freeradius-ldap'
		+' < /dev/null > build_ldap_client.log 2>&1'
	)
	commands = [
		f'echo {base64_encode_string('--- Radius Server log begins ---')} | base64 -d >> build_radius_server.log',
		install_string,
	]
	return commands

def commands_config_radius_server(node):
	commands = [
		'echo "libpam-runtime libpam-runtime/profiles multiselect unix, ldap, create-home" | debconf-set-selections',
		'pam-auth-update --package',
		'echo "session required pam_mkhomedir.so skel=/etc/skel umask=077" >> /etc/pam.d/common-session',
	]
	#commands += push_file_hex_commands(node, "/etc/ssh/sshd_config", "644", debian_sshd_content(node))
	commands += push_file_hex_commands(node, "/etc/freeradius/3.0/mods-config/files/authorize", "644", radius_server_authorize_content(node))
	commands += push_file_hex_commands(node, "/etc/freeradius/3.0/clients.conf", "644", radius_server_clients_content(node))
	commands.append("systemctl restart ssh; systemctl restart freeradius; systemctl restart nslcd")
	return commands

def radius_server_authorize_content(radius_server_1: Node):
	topology = None
	prox1 = None
	container = None
	topology = radius_server_1.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	container = prox1.get_container(radius_server_1.hostname)
	if container is None:
		raise ValueError("container is None")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	#region return string
	return '''
"john"	Cleartext-Password := "nhoj"
	Reply-Message = "Radius %{User-Name}",
	Service-Type = NAS-Prompt-User,
	Cisco-AVPair = "shell:priv-lvl=15",
	Class = "network_admin"
"dave"	Cleartext-Password := "evad"
	Reply-Message = "Radius %{User-Name}",
	Service-Type = NAS-Prompt-User,
	Class = "sales"
"radlab"	Cleartext-Password := "bal"
	Reply-Message = "Radius %{User-Name}",
	Service-Type = NAS-Prompt-User,
	Cisco-AVPair = "shell:priv-lvl=15",
	Class = "network_admin"
"radauto"	Cleartext-Password := "otua"
	Reply-Message = "Radius %{User-Name}",
	Service-Type = NAS-Prompt-User,
	Cisco-AVPair = "shell:priv-lvl=15",
	Class = "network_admin"

DEFAULT Class == "network_admin", NAS-Identifier =~ "Net-Cisco-B@4]"
	Reply-Message = "Admin Access Granted"

DEFAULT Class != "network_admin", NAS-Identifier =~ "Net-Cisco-B@4]"
	Reply-Message := "Access Denied: You do not have the appropriate permissions",
	Auth-Type := Reject

DEFAULT Class == "network_admin", NAS-IP-Address == "192.168.250.101"
	Reply-Message = "Admin Access Granted"
	
DEFAULT Class != "network_admin", NAS-IP-Address == "192.168.250.101"
	Reply-Message := "Access Denied: You do not have the appropriate permissions",
	Auth-Type := Reject

DEFAULT Class == "network_admin", NAS-IP-Address == "127.0.0.1"
	Reply-Message = "Admin Access Granted"
	
DEFAULT Class != "network_admin", NAS-IP-Address == "127.0.0.1"
	Reply-Message := "Access Denied: You do not have the appropriate permissions",
	Auth-Type := Reject

DEFAULT Class == "network_admin", NAS-IP-Address == "10.131.70.251"
	Reply-Message = "Admin Access Granted"
	
DEFAULT Class != "network_admin", NAS-IP-Address == "10.131.70.251"
	Reply-Message := "Access Denied: You do not have the appropriate permissions",
	Auth-Type := Reject

DEFAULT	Framed-Protocol == PPP
	Framed-Protocol = PPP,
	Framed-Compression = Van-Jacobson-TCP-IP

DEFAULT	Hint == "CSLIP"
	Framed-Protocol = SLIP,
	Framed-Compression = Van-Jacobson-TCP-IP

DEFAULT	Hint == "SLIP"
	Framed-Protocol = SLIP
'''
	#endregion

def radius_server_clients_content(radius_server_1: Node):
	topology = None
	prox1 = None
	container = None
	topology = radius_server_1.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	container = prox1.get_container(radius_server_1.hostname)
	if container is None:
		raise ValueError("container is None")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	#region return string
	return f"""
client localhost{{
ipaddr = 127.0.0.1
secret = beantruck
shortname = localhost
}}
client r1.tapeitup.private {{
	ipaddr = {topology.get_node("r1").get_interface("loopback","0").ipv4_address}
	secret = r1radiuskey
	shortname = r1
}}
client sw3.tapeitup.private {{
	ipaddr = {topology.get_node("sw3").get_interface("loopback", "0").ipv4_address}
	secret = sw3radiuskey
	shortname = sw3
}}
	"""
	#endregion
	
def radius_server_pam_radius_auth_content(radius_server_1: Node): # This is currently unused?
	#region return string
	return """
127.0.0.1    beantruck             1
other-server    other-secret       3
"""
	#endregion

def radius_server_sshd_content(radius_server_1: Node): # This is for making radius requests for Linux ssh auth not ldap? Probably not needed
	#region return string
	return """
auth    required    pam_radius_auth.so
@include common-auth
account    required     pam_nologin.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
@include common-session
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv
session    required     pam_limits.so
session    required     pam_env.so
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open
@include common-password
"""
	#endregion
