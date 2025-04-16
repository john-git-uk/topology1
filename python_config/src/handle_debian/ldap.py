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

def commands_packages_ldap_client(node):
	#region docstring
	'''
	Provides commands for debian based systems for installing the packages required for participating in LDAP as a client.
	'''
	#endregion
	install_string = (
		'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends' 
		+' libpam-ldapd'
		+' libnss-ldap'
		+' ldap-utils'
		+' libldap-2.5-0'
		+' libldap-common'
		+' nslcd'
		+' nscd'
		+' < /dev/null > build_ldap_client.log 2>&1'
	)
	commands = [
		f'echo {base64_encode_string('--- ldap-client log begins ---')} | base64 -d >> build_ldap_client.log',
		install_string,
	]
	return commands

def ldap_server_ldap_base_content(node):
	#region return string
	topology = node.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	return f"""
dn: ou=People,dc={topology.domain_name_a},dc={topology.domain_name_b}
objectClass: organizationalUnit
ou: People

dn: ou=Groups,dc={topology.domain_name_a},dc={topology.domain_name_b}
objectClass: organizationalUnit
ou: Groups

# Network Admin Group
dn: cn=network_admin,ou=Groups,dc={topology.domain_name_a},dc={topology.domain_name_b}
objectClass: posixGroup
cn: network_admin
gidNumber: 10001

# Sales Group
dn: cn=sales,ou=Groups,dc={topology.domain_name_a},dc={topology.domain_name_b}
objectClass: posixGroup
cn: sales
gidNumber: 10002

# User John
dn: uid=john,ou=People,dc={topology.domain_name_a},dc={topology.domain_name_b}
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: john
sn: none
givenName: john
uid: john
uidNumber: 1001
gidNumber: 10001
homeDirectory: /home/john
loginShell: /bin/bash
mail: john@tapeitup.private
userPassword: {{SSHA}}VrHa6dK8wDewHUmn1begyCJNmq9SIwt1

# User Dave
dn: uid=dave,ou=People,dc={topology.domain_name_a},dc={topology.domain_name_b}
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: dave
sn: none
givenName: dave
uid: dave
uidNumber: 1002
gidNumber: 10002
homeDirectory: /home/dave
loginShell: /bin/bash
mail: dave@tapeitup.private
userPassword: {{SSHA}}CU6BdjNWkngd4snNvl4k6A6jBHPbNmAw
"""
	#endregion

def ldap_server_php_webgui_content(node):
	#region return string
	return f"""
<?php
$config->custom->appearance["friendly_attrs"] = array(
	"facsimileTelephoneNumber" => "Fax",
	"gid"                      => "Group",
	"mail"                     => "Email",
	"telephoneNumber"          => "Telephone",
	"uid"                      => "User Name",
	"userPassword"             => "Password"
);

$servers = new Datastore();
$servers->newServer("ldap_pla");
$servers->setValue("server","name","My LDAP Server");
$servers->setValue("server","host","{node.oob_interface.ipv4_address}");
$servers->setValue("server","base",array("dc={node.topology_a_part_of.domain_name_a},dc={node.topology_a_part_of.domain_name_b}"));
$servers->setValue("login","bind_id","cn=admin,dc={node.topology_a_part_of.domain_name_a},dc={node.topology_a_part_of.domain_name_b}");
?>
"""
	#endregion

def ldap_server_logging_ldif_content():
	""" This content is part of ldap server configuration """
	#region return string
	return f"""
dn: cn=config
changetype: modify
replace: olcLogLevel
olcLogLevel: stats

dn: cn=config
changetype: modify
add: olcPasswordHash
olcPasswordHash: {{SSHA}}
"""
	#endregion

def ldap_client_nslcd_content(node):
	topology = None
	container = None
	topology = node.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	ldap_server_1 = topology.get_node("ldap-server-1") # TODO: Assumed there is only one ldap server
	if ldap_server_1 is None:
		raise ValueError("ldap_server_1 not found")
	#region return string
	return f"""
uri ldap://{ldap_server_1.get_interface("ethernet","eth1").ipv4_address}
base dc={topology.domain_name_a},dc={topology.domain_name_b}
binddn cn=admin,dc={topology.domain_name_a},dc={topology.domain_name_b}
bindpw ldap
"""
	#endregion

def ldap_client_nsswitch_content():
	""" This content is part of ldap client configuration """
	#region return string
	return f"""
passwd:         compat ldap
group:          compat ldap
shadow:         compat ldap
"""
	#endregion

def commands_packages_ldap_server(node):
	#region docstring
	'''
	Provides commands for Debian based systems for configuring the provision of LDAP services.
	'''
	#endregion

	topology = None
	topology = node.topology_a_part_of
	if topology is None:
		LOGGER.error("topology is None")
		return	
	############################################
	commands = [
		f'echo {base64_encode_string(f"echo nslcd nslcd/ldap-uris string ldap://{node.get_interface('ethernet','eth1').ipv4_address}:389/ | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/internal/generated_adminpw password ldap | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/internal/adminpw password ldap | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/password1 password ldap | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/password2 password ldap | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string(f"echo slapd slapd/domain string {topology.domain_name_a}.{topology.domain_name_b} | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string(f"echo slapd shared/organization string {topology.domain_name_a} | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/no_configuration boolean false | debconf-set-selections")} | base64 -d | sh',
	]
	commands += [
		'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends    '
		+'slapd ldapscripts libpam-ldap libldap-common apache2 php libapache2-mod-php nscd phpldapadmin',
	]
	return commands

def commands_config_ldap_client(node):
	#region docstring
	'''
	Provides commands for Debian based systems for configuring participation in LDAP as a client.
	'''
	#endregion

	topology = None
	topology = node.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	###################
	commands = [(
		f'echo {base64_encode_string('echo "libpam-runtime libpam-runtime/profiles multiselect unix, ldap, create-home" | debconf-set-selections')} | base64 -d | sh'
		+ '; pam-auth-update --package'
		+ f' ; echo {base64_encode_string('echo "session required pam_mkhomedir.so skel=/etc/skel umask=077" >> /etc/pam.d/common-session')} | base64 -d | bash'
		+ " ; systemctl restart nscd ; systemctl restart nslcd"
	)]
	commands += push_file_hex_commands(node, "/etc/nslcd.conf", "600", ldap_client_nslcd_content(node))
	commands += push_file_hex_commands(node, "/etc/nsswitch.conf", "644", ldap_client_nsswitch_content())
	
	return commands

def commands_config_ldap_server(node):
	#region docstring
	'''
	Provides commands for Debian based systems for configuring the provision of LDAP services.
	'''
	#endregion
	topology = None
	topology = node.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	###################
	commands = []
	commands += (push_file_hex_commands(node, "/root/base.ldif", "644", ldap_server_ldap_base_content(node)))
	commands += (push_file_hex_commands(node, "/etc/phpldapadmin/config.php", "644", ldap_server_php_webgui_content(node)))
	commands += (push_file_hex_commands(node, "/root/logging.ldif", "644", ldap_server_logging_ldif_content()))
	commands.append(f"ldapadd -x -D cn=admin,dc={topology.domain_name_a},dc={topology.domain_name_b} -w ldap -f /root/base.ldif"
	+f" ;ldapadd -Y EXTERNAL -H ldapi:/// -f /root/logging.ldif")
	commands.append("systemctl restart ssh ; systemctl restart slapd ; systemctl restart apache2")

	return commands