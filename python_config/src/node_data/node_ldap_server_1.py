from __future__ import annotations
import paramiko
from handle_debian import *
import logging
from convert import get_escaped_string, get_chunky_hex, base64_encode_string
from interface import Interface
from node import Node
from handle_proxmox import Container, execute_proxnode_commands, start_container, wait_for_container_ping_debian, wait_for_container_running
import time
import base64
LOGGER = logging.getLogger('my_logger')
def ldap_server_1_structures(topology: Topology):
	from machine_data import get_machine_data

	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	ldap_server1_i1 = Interface(
		name="eth0",
		interface_type="ethernet",
		ipv4_address="192.168.2.231",
		ipv4_cidr=24
	)

	ldap_server1_i2 = Interface(
		name="eth1",
		interface_type="ethernet",
		ipv4_address="10.133.60.250",
		ipv4_cidr=24
	)
	ldap_server1 = Node(
		hostname="ldap-server-1",
		machine_data=get_machine_data("debian"),
		oob_interface=ldap_server1_i1,
		local_user="root",
		local_password="12345",
		hypervisor_telnet_port=0,
	)
	ldap_server1_container = Container(
		ctid=201,
		template="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
		memory=512,
		cores=1,
		rootfs="local:8",
		resource_pool = "default",
		disk_size=8,
		node_a_part_of=prox1,
		node_data=ldap_server1,
	)
	ldap_server1.add_interface(ldap_server1_i1)
	ldap_server1.add_interface(ldap_server1_i2)
	prox1.topology_a_part_of.add_node(ldap_server1)
	prox1.add_container(ldap_server1_container)
def ldap_server_1_relations(topology: Topology):
	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	ldap_server_1 = None
	ldap_server_1 = topology.get_node("ldap-server-1")
	
	if(ldap_server_1 is None):
		raise Exception("ldap_server_1 is None")

	ldap_server_1.get_interface("ethernet","eth0").connect_to(prox1.get_interface("bridge","oob_hitch"))
	ldap_server_1.get_interface("ethernet","eth1").connect_to(prox1.get_interface("bridge","vmbr60"))

def packages_time_ldap_server_1(ldap_server_1):
	topology = None
	prox1 = None
	container = None
	topology = ldap_server_1.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	container = prox1.get_container(ldap_server_1.hostname)
	if container is None:
		raise ValueError("container is None")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	if not wait_for_container_running(prox1, container, 30):
		LOGGER.error(f"Container {ldap_server_1.hostname} did not start in time")
		return
	if not wait_for_container_ping_debian(prox1, container, 30):
		LOGGER.error(f"Container {ldap_server_1.hostname} cannot contact debian.org")
		return
	
	commands = []
	commands += [
		'apt-get update',
		'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends locales',
		"sed -i '/en_GB.UTF-8/s/^# //g' /etc/locale.gen",
		'locale-gen en_GB.UTF-8',
		'update-locale LANG=en_GB.UTF-8 LC_ALL=en_GB.UTF-8',
		"echo 'LANG=\"en_GB.UTF-8\"' > /etc/default/locale",
		"echo 'LC_ALL=\"en_GB.UTF-8\"' >> /etc/default/locale",
		#f'echo "nslcd nslcd/ldap-uris string ldap://{ldap_server_1.get_interface("eth1").ipv4_address}:389/" | debconf-set-selections',
		#'echo "slapd slapd/internal/generated_adminpw password ldap" | debconf-set-selections',
		#'echo "slapd slapd/internal/adminpw password ldap" | debconf-set-selections',
		#'echo "slapd slapd/password1 password ldap" | debconf-set-selections',
		#'echo "slapd slapd/password2 password ldap" | debconf-set-selections',
		#f'echo "slapd slapd/domain string {topology.domain_name_a}.{topology.domain_name_b}" | debconf-set-selections',
		#f'echo "slapd shared/organization string {topology.domain_name_a}" | debconf-set-selections',
		#'echo "slapd slapd/no_configuration boolean false" | debconf-set-selections',
		f'echo {base64_encode_string(f"echo nslcd nslcd/ldap-uris string ldap://{ldap_server_1.get_interface('eth1').ipv4_address}:389/ | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/internal/generated_adminpw password ldap | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/internal/adminpw password ldap | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/password1 password ldap | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/password2 password ldap | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string(f"echo slapd slapd/domain string {topology.domain_name_a}.{topology.domain_name_b} | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string(f"echo slapd shared/organization string {topology.domain_name_a} | debconf-set-selections")} | base64 -d | sh',
		f'echo {base64_encode_string("echo slapd slapd/no_configuration boolean false | debconf-set-selections")} | base64 -d | sh',
		'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends xxd telnet curl openssh-client'
		+' openssh-server nano vim-tiny iputils-ping build-essential slapd ldap-utils ldapscripts libpam-ldap'
		+' net-tools iproute2 rsyslog libldap-2.5-0 libldap-common apache2 php libapache2-mod-php'
		+' libpam-ldapd nslcd nscd phpldapadmin sudo libnss-ldap',
	]
	
	output,error = execute_proxnode_commands(prox1, ldap_server_1, commands)

def configure_ldap_server_1(ldap_server_1):
	topology = None
	prox1 = None
	container = None
	topology = ldap_server_1.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	container = prox1.get_container(ldap_server_1.hostname)
	if container is None:
		raise ValueError("container is None")

	if not wait_for_container_running(prox1, container, 30):
		LOGGER.error(f"Container {ldap_server_1.hostname} did not start in time")
		return
	if not wait_for_container_ping_debian(prox1, container, 30):
		LOGGER.error(f"Container {ldap_server_1.hostname} cannot contact debian.org")
		return
	###################
	commands = []
	LOGGER.debug("changesssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss")
	commands += [
		f'echo {base64_encode_string('echo "libpam-runtime libpam-runtime/profiles multiselect unix, ldap, create-home" | debconf-set-selections')} | base64 -d | sh',
		'pam-auth-update --package',
		f'echo {base64_encode_string('echo "session required pam_mkhomedir.so skel=/etc/skel umask=077" >> /etc/pam.d/common-session')} | base64 -d | bash',
	]
	commands += push_file_commands(ldap_server_1, "/etc/ssh/sshd_config", "644", get_escaped_string(ldap_server_1_sshd_content(ldap_server_1)))
	commands += push_file_commands(ldap_server_1, "/root/base.ldif", "644", get_escaped_string(ldap_server_1_ldap_base_content(ldap_server_1)))
	commands += push_file_hex_commands(ldap_server_1, "/etc/phpldapadmin/config.php", "644", ldap_server_1_php_webgui_content(ldap_server_1))
	commands += push_file_commands(ldap_server_1, "/root/logging.ldif", "644", get_escaped_string(ldap_server_1_logging_ldif_content(ldap_server_1)))
	commands += push_file_commands(ldap_server_1, "/etc/nslcd.conf", "600", get_escaped_string(ldap_server_1_nslcd_content(ldap_server_1)))
	commands += push_file_commands(ldap_server_1, "/etc/nsswitch.conf", "644", get_escaped_string(ldap_server_1_nsswitch_content(ldap_server_1)))
	commands += [f"ldapadd -x -D cn=admin,dc={topology.domain_name_a},dc={topology.domain_name_b} -w ldap -f /root/base.ldif"]
	commands += [f"ldapadd -Y EXTERNAL -H ldapi:/// -f /root/logging.ldif"]
	commands += ["systemctl restart ssh",  "systemctl restart slapd", "systemctl restart nslcd", "systemctl restart nscd", "systemctl restart apache2"]
	
	output,error = execute_proxnode_commands(prox1, ldap_server_1, commands)

def ldap_server_1_sshd_content(ldap_server_1):
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
ListenAddress {ldap_server_1.oob_interface.ipv4_address}
"""
	#endregion
def ldap_server_1_ldap_base_content(ldap_server_1):
	#region return string
	topology = ldap_server_1.topology_a_part_of
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
def ldap_server_1_php_webgui_content(ldap_server_1):
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
$servers->setValue("server","host","{ldap_server_1.oob_interface.ipv4_address}");
$servers->setValue("server","base",array("dc={ldap_server_1.topology_a_part_of.domain_name_a},dc={ldap_server_1.topology_a_part_of.domain_name_b}"));
$servers->setValue("login","bind_id","cn=admin,dc={ldap_server_1.topology_a_part_of.domain_name_a},dc={ldap_server_1.topology_a_part_of.domain_name_b}");
?>
"""
	#endregion
def ldap_server_1_logging_ldif_content(ldap_server_1):
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
def ldap_server_1_nslcd_content(ldap_server_1):
	#region return string
	return f"""
uri ldap://127.0.0.1
base dc=tapeitup,dc=private
binddn cn=admin,dc=tapeitup,dc=private
bindpw ldap
"""
	#endregion
def ldap_server_1_nsswitch_content(ldap_server_1):
	#region return string
	return f"""
passwd:         compat ldap
group:          compat ldap
shadow:         compat ldap
"""
	#endregion