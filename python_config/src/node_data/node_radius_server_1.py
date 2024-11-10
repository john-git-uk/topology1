from __future__ import annotations
import paramiko
from handle_debian import *
import logging
from convert import get_escaped_string
from interface import Interface
from node import Node
from handle_proxmox import Container, execute_proxnode_commands, start_container, wait_for_container_ping_debian, wait_for_container_running
from project_globals import GLOBALS
LOGGER = logging.getLogger('my_logger')
def radius_server_1_structures(topology: Topology):
	from machine_data import get_machine_data
	for segs in topology.access_segments:
		if(segs.name == "main"):
			access_segment = segs
	if(access_segment is None):
		LOGGER.error("Access segment main not found")
		return

	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	radius_server1_i1 = Interface(
		name="eth0",
		interface_type="ethernet",
		ipv4_address="192.168.2.230",
		ipv4_cidr=24
	)
	radius_server1_i2 = Interface(
		name="eth1",
		interface_type="ethernet",
		ipv4_address="10.133.60.251",
		ipv4_cidr=24
	)
	radius_server1 = Node(
		hostname="radius-server-1",
		machine_data=get_machine_data("debian"),
		oob_interface=radius_server1_i1,
		identity_interface=radius_server1_i2,
		local_user=GLOBALS.radius_server_1_username,
		local_password=GLOBALS.radius_server_1_password,
		hypervisor_telnet_port=0,
	)
	radius_server1_container = Container(
		ctid=202,
		template="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
		memory=512,
		cores=1,
		rootfs="local:8",
		resource_pool = "default",
		disk_size=8,
		node_a_part_of=prox1,
		node_data=radius_server1,
	)
	radius_server1.add_interface(radius_server1_i1)
	radius_server1.add_interface(radius_server1_i2)
	prox1.topology_a_part_of.add_node(radius_server1)
	prox1.add_container(radius_server1_container)
	access_segment.nodes.append(radius_server1)
	radius_server1.access_segment=access_segment

def radius_server_1_relations(topology: Topology):
	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	radius_server_1 = None
	radius_server_1 = topology.get_node("radius-server-1")
	
	if(radius_server_1 is None):
		raise Exception("radius_server_1 is None")
	
	radius_server_1.get_interface("ethernet","eth0").connect_to(prox1.get_interface("bridge","oob_hitch"))
	radius_server_1.get_interface("ethernet","eth1").connect_to(prox1.get_interface("bridge","vmbr60"))

def packages_time_radius_server_1(radius_server_1: Node):
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

	if not wait_for_container_running(prox1, container, 30):
		LOGGER.error(f"Container {radius_server_1.hostname} did not start in time")
		return
	if not wait_for_container_ping_debian(prox1, container, 30):
		LOGGER.error(f"Container {radius_server_1.hostname} cannot contact debian.org")
		return

	commands = ["ping -c 3 debian.org"]
	ping_output,ping_error = execute_proxnode_commands(prox1, radius_server_1, commands)
	ping_output_str = ''.join(ping_output)
	# Check the result of the ping command
	if "0% packet loss" in ping_output_str:
		LOGGER.debug("#### debian.org is reachable!")
	else:
		LOGGER.error("#### debian.org is NOT reachable!")
		LOGGER.debug(f"#### Ping Output: {ping_output}")
		LOGGER.debug(f"#### Ping Error: {ping_error}")
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
		'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends telnet curl openssh-client openssh-server nano '
		+'vim-tiny iputils-ping build-essential net-tools freeradius freeradius-utils iproute2 libpam-radius-auth freeradius-ldap rsyslog xxd '
		+'libpam-ldapd nslcd sudo libnss-ldap ldap-utils libldap-2.5-0 libldap-common',
	]
	output,error = execute_proxnode_commands(prox1, radius_server_1, commands)

def configure_radius_server_1(radius_server_1: Node):
	LOGGER.debug("#### Configuring radius-server-1")
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

	if not wait_for_container_running(prox1, container, 30):
		LOGGER.error(f"Container {radius_server_1.hostname} did not start in time")
		return
	if not wait_for_container_ping_debian(prox1, container, 30):
		LOGGER.error(f"Container {radius_server_1.hostname} cannot contact debian.org")
		return

	commands = []
	commands += [
		'echo "libpam-runtime libpam-runtime/profiles multiselect unix, ldap, create-home" | debconf-set-selections',
		'pam-auth-update --package',
		'echo "session required pam_mkhomedir.so skel=/etc/skel umask=077" >> /etc/pam.d/common-session',
	]
	commands += push_file_commands(radius_server_1, "/etc/ssh/sshd_config", "644", get_escaped_string(radius_server_1_sshd_config_content(radius_server_1)))
	commands += push_file_commands(radius_server_1, "/etc/freeradius/3.0/mods-config/files/authorize", "644", get_escaped_string(radius_server_1_authorize_content(radius_server_1)))
	commands += push_file_commands(radius_server_1, "/etc/freeradius/3.0/clients.conf", "644", get_escaped_string(radius_server_1_clients_content(radius_server_1)))
	commands += push_file_commands(radius_server_1, "/etc/nslcd.conf", "600", get_escaped_string(radius_server_1_nslcd_content(radius_server_1)))
	commands += push_file_commands(radius_server_1, "/etc/nsswitch.conf", "644", get_escaped_string(radius_server_1_nsswitch_content(radius_server_1)))
	commands += ["systemctl restart ssh", "systemctl restart freeradius", "systemctl restart nslcd"]

	output,error = execute_proxnode_commands(prox1, radius_server_1, commands)
def radius_server_1_authorize_content(radius_server_1: Node):
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
def radius_server_1_clients_content(radius_server_1: Node):
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
client R1.tapeitup.private {{
	ipaddr = {topology.get_node("R1").get_interface("loopback","0").ipv4_address}
	secret = R1radiuskey
	shortname = R1
}}
client SW3.tapeitup.private {{
	ipaddr = {topology.get_node("SW3").get_interface("loopback", "0").ipv4_address}
	secret = SW3radiuskey
	shortname = SW3
}}
	"""
	#endregion
def radius_server_1_pam_radius_auth_content(radius_server_1: Node):
	#region return string
	return """
127.0.0.1    beantruck             1
other-server    other-secret       3
"""
	#endregion
def radius_server_1_sshd_content(radius_server_1: Node): # This is for making radius requests for Linux ssh auth not ldap? Probably not needed
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

def radius_server_1_sshd_config_content(radius_server_1: Node):
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
ListenAddress {radius_server_1.oob_interface.ipv4_address}
"""
	#endregion
def radius_server_1_nslcd_content(radius_server_1):
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
	ldap_server_1 = topology.get_node("ldap-server-1") # TODO: Assumed there is only one ldap server
	#region return string
	return f"""
uri ldap://{ldap_server_1.get_interface("ethernet","eth1").ipv4_address}
base dc={topology.domain_name_a},dc={topology.domain_name_b}
binddn cn=admin,dc={topology.domain_name_a},dc={topology.domain_name_b}
bindpw ldap
"""
	#endregion
def radius_server_1_nsswitch_content(radius_server_1):
	#region return string
	return f"""
passwd:         compat ldap
group:          compat ldap
shadow:         compat ldap
"""
	#endregion
