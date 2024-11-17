from __future__ import annotations
import random
import string
from convert import get_escaped_string, get_chunky_hex, base64_encode_string, get_escaped_string
import logging
LOGGER = logging.getLogger('my_logger')
import requests
from project_globals import GLOBALS

def push_file_commands(node, dest_file, chmod, content):
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
	if node.machine_data.device_type != "debian":
		ValueError(f"Node {node.hostname} is not a debian node!")
	
	commands = [
		(
			f"rm {dest_file}"
			+f"; touch {dest_file}"
			+f"; chmod {chmod} {dest_file}"
		),
	]
	chunky_hex = []
	chunky_hex = get_chunky_hex(content)
	LOGGER.debug(f"chunky_hex: {chunky_hex}")
	for chunk in chunky_hex:
		commands.append(f"echo -n '{chunk}' | xxd -r -p >> {dest_file}")
	return commands

def container_repo_reachability_check(container):
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

def commands_packages_essential(node):
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
		+ " 2>&1 | tee -a /var/log/locale-setup.log"
	)
	
	commands += [
		install_string,
		'apt-get upgrade -y < /dev/null >> build_essential.log 2>&1',
	]
	return commands

def commands_packages_ldap_client(node):
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

def commands_packages_pi_hole(node):
	# Retrieve the pihole install script
	response = requests.get('https://raw.githubusercontent.com/pi-hole/pi-hole/master/automated%20install/basic-install.sh')
	if response.status_code == 200:
		file_content = response.text
	else:
		LOGGER.error("Failed to retrieve the pihole install script:", response.status_code)
	commands = push_file_hex_commands(node, 'basic-install.sh', '755', file_content)

	if node == None:
		LOGGER.error("handle_debian commands_packages_pi_hole: passed node is None")
		return
	if node.topology_a_part_of == None:
		LOGGER.error("handle_debian commands_packages_pi_hole: passed node has no topology")
		return
	topology = node.topology_a_part_of

	install_string = (
		'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends' 
		+' lighttpd-mod-openssl'
		+' cron'
		+' curl'
		+' php8.2-common'
		+' php8.2-xml'
		+' php8.2-sqlite3'
		+' php8.2-cgi'
		+' php8.2-intl'
		+' lighttpd'
		+' jq'
		+' procps'
		+' dns-root-data'
		+' idn2'
		+' unzip'
		+' libcap2-bin'
		+' iputils-ping'
		+' < /dev/null > build_ldap_client.log 2>&1'
	)
	commands += [
		f'echo {base64_encode_string('--- Pi Hole log begins ---')} | base64 -d >> build_pi_hole.log',
		install_string,
	]
	commands += [
		("mkdir -p /etc/pihole/"
		#+f"; sed -i '2i export CURL_CONNECT_TIMEOUT=5' basic-install.sh ; sed -i '2i export CURL_MAX_TIME=10' basic-install.sh"
		+f"; echo 'PIHOLE_INTERFACE={node.get_interface("ethernet",'eth1').name}' > /etc/pihole/setupVars.conf"
		+f"; echo 'IPV4_ADDRESS={node.get_interface("ethernet",'eth1').ipv4_address}/" # TODO: No Hardcoded IP
		+f"{node.get_interface("ethernet",'eth1').ipv4_cidr}' >> /etc/pihole/setupVars.conf"
		+f"; echo 'QUERY_LOGGING=false' >> /etc/pihole/setupVars.conf"
		+f"; echo 'INSTALL_WEB_SERVER=true' >> /etc/pihole/setupVars.conf"
		+f"; echo 'WEBPASSWORD={GLOBALS.dns_web_api_password}' >> /etc/pihole/setupVars.conf"
		+f"; echo 'PIHOLE_DNS_1={str(topology.dns_upstream[0])}' >> /etc/pihole/setupVars.conf"),
		"PIHOLE_SKIP_OS_CHECK=true bash basic-install.sh --unattended",
	]
	if len(topology.dns_upstream) > 1:
		commands += [f"echo 'PIHOLE_DNS_2={str(topology.dns_upstream[1])}' >> /etc/pihole/setupVars.conf"]
	if len(topology.dns_upstream) > 2:
		commands += [f"echo 'PIHOLE_DNS_3={str(topology.dns_upstream[2])}' >> /etc/pihole/setupVars.conf"]
	if len(topology.dns_upstream) > 3:
		commands += [f"echo 'PIHOLE_DNS_4={str(topology.dns_upstream[3])}' >> /etc/pihole/setupVars.conf"]
	if len(topology.dns_upstream) > 4:
		LOGGER.warning(f"Only 4 upstream DNS servers are used in the code, but {len(topology.dns_upstream)}" 
		+f" were provided when configuring {node.hostname} pi hole upstream")
	return commands

def commands_packages_radius_server(node):
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

def commands_config_pi_hole(node):
	topology = None
	topology = node.topology_a_part_of
	if topology is None:
		LOGGER.error("topology is None")
		return	
	################################################
	cert_string = ("openssl req -x509 -newkey rsa:2048 -keyout /etc/ssl/private/lighttpd.key -out" 
	f" /etc/ssl/certs/lighttpd.pem -days 365 -nodes -subj '/C=UK/ST=State/L=City/O=Organization/OU=OrgUnit/CN={topology.domain_name_a}.{topology.domain_name_b}'"
	)
	commands = [
		f'echo {base64_encode_string(pi_lighttpd_conf(node))} | base64 -d > /etc/lighttpd/lighttpd.conf',
		"mkdir -p /etc/ssl/certs /etc/ssl/private",
		f'echo {base64_encode_string(cert_string)} | base64 -d | sh',
		"rm -f /etc/dnsmasq.d/custom.conf",
		"mkdir -p /etc/dnsmasq.d",
		"touch /etc/dnsmasq.d/custom.conf",
		"chmod 644 /etc/dnsmasq.d/custom.conf",
		f'echo {base64_encode_string(pi_dnsmasq_custom(node))} | base64 -d > /etc/dnsmasq.d/custom.conf',
		"/usr/local/bin/pihole logging on",
		"systemctl restart lighttpd",
		"systemctl restart pihole-FTL",
	]
	commands += [
		"rm -f /etc/dnsmasq.d/local.conf",
		"mkdir -p /etc/dnsmasq.d",
		"touch /etc/dnsmasq.d/local.conf",
		"chmod 644 /etc/dnsmasq.d/local.conf",
	]
	for node in topology.nodes:
		main_interface = None
		if node.hostname is None:
			LOGGER.error(f"A Node does not have a hostname")
			continue
		if node.get_interface_count() < 1:
			LOGGER.error(f"Node {node.hostname} does not have any interfaces")
			continue
		for i in range(node.get_interface_count()-1):
			interface = node.get_interface_no(i)
			if interface.ipv4_address is None:
				continue
			int_str = ""
			if node.machine_data.device_type == "cisco_ios" or node.machine_data.device_type == "cisco_xe":
				int_str = interface.interface_type
				int_str += "-"
			int_str += interface.name
			int_str = int_str.replace(" ", "-").replace("/","-")
			commands += [
				f'echo {base64_encode_string(
					f'echo "address=/{int_str}.{node.hostname}.{topology.domain_name_a}.{topology.domain_name_b}/{interface.ipv4_address}" >> /etc/dnsmasq.d/local.conf'
				)} | base64 -d | sh',
			]
		if node.get_identity_interface() is None:
			LOGGER.warning(f"Could not find main interface for {node.hostname} DNS entry")
			continue
		commands += [
			f'echo {base64_encode_string(
				f'echo "address=/{node.hostname}.{topology.domain_name_a}.{topology.domain_name_b}/{node.get_identity_interface().ipv4_address}" >> /etc/dnsmasq.d/local.conf'
			)} | base64 -d | sh',
		]
	commands += [
		"systemctl restart pihole-FTL",
		"rm -f /etc/resolv.conf",
		"touch /etc/resolv.conf",
		"chmod 644 /etc/resolv.conf",
	]
	for dns in topology.dns_private:
		commands += [
			f"echo 'nameserver {dns.ipv4_address}' >> /etc/resolv.conf",
		]
		for upstream in topology.dns_upstream:
			commands += [
				f"if ! grep -q '^server={str(upstream)}$' /etc/dnsmasq.d/01-pihole.conf; then echo 'server={str(upstream)}' >> /etc/dnsmasq.d/01-pihole.conf; fi",
			]
	return commands

def commands_packages_ldap_server(node):
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
	topology = None
	topology = node.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	###################
	commands = []
	commands += (push_file_hex_commands(node, "/etc/ssh/sshd_config", "644", debian_sshd_content(node)))
	commands += (push_file_hex_commands(node, "/root/base.ldif", "644", ldap_server_ldap_base_content(node)))
	commands += (push_file_hex_commands(node, "/etc/phpldapadmin/config.php", "644", ldap_server_php_webgui_content(node)))
	commands += (push_file_hex_commands(node, "/root/logging.ldif", "644", ldap_server_logging_ldif_content()))
	commands.append(f"ldapadd -x -D cn=admin,dc={topology.domain_name_a},dc={topology.domain_name_b} -w ldap -f /root/base.ldif"
	+f" ;ldapadd -Y EXTERNAL -H ldapi:/// -f /root/logging.ldif")
	commands.append("systemctl restart ssh ; systemctl restart slapd ; systemctl restart apache2")

	return commands

def commands_config_radius_server(node):
	commands = [
		'echo "libpam-runtime libpam-runtime/profiles multiselect unix, ldap, create-home" | debconf-set-selections',
		'pam-auth-update --package',
		'echo "session required pam_mkhomedir.so skel=/etc/skel umask=077" >> /etc/pam.d/common-session',
	]
	commands += push_file_hex_commands(node, "/etc/ssh/sshd_config", "644", debian_sshd_content(node))
	commands += push_file_hex_commands(node, "/etc/freeradius/3.0/mods-config/files/authorize", "644", radius_server_authorize_content(node))
	commands += push_file_hex_commands(node, "/etc/freeradius/3.0/clients.conf", "644", radius_server_clients_content(node))
	commands.append("systemctl restart ssh; systemctl restart freeradius; systemctl restart nslcd")
	return commands

def pi_lighttpd_conf(node: Node):
	if node is None:
		LOGGER.error(f"No node in pi_dnsmasq_custom")
		return ""
	if node.oob_interface is None:
		LOGGER.error(f"No OOB interface for {node.hostname} pi hole")
		return ""
	#region return string
	return f"""
server.modules = (
		"mod_indexfile",
		"mod_access",
		"mod_alias",
		"mod_redirect",
)

server.document-root        = "/var/www/html"
server.upload-dirs          = ( "/var/cache/lighttpd/uploads" )
server.errorlog             = "/var/log/lighttpd/error.log"
server.pid-file             = "/run/lighttpd.pid"
server.username             = "www-data"
server.groupname            = "www-data"
server.port                 = 8443

server.feature-flags       += ("server.h2proto" => "enable")
server.feature-flags       += ("server.h2c"     => "enable")
server.feature-flags       += ("server.graceful-shutdown-timeout" => 5)

#$SERVER["socket"] == "{node.oob_interface.ipv4_address}:8443" {{
#	ssl.engine                 = "enable"
#	ssl.pemfile                = "/etc/ssl/certs/lighttpd.pem"
#	ssl.privkey                = "/etc/ssl/private/lighttpd.key"
#}}
setenv.add-environment = ("fqdn" => "true")
$SERVER["socket"] == ":8443" {{
	ssl.engine  = "enable"
	ssl.pemfile  = "/etc/ssl/certs/lighttpd.pem"
	ssl.privkey  = "/etc/ssl/private/lighttpd.key"
	ssl.openssl.ssl-conf-cmd = ("MinProtocol" => "TLSv1.3", "Options" => "-ServerPreference")
}}

# Redirect HTTP to HTTPS
$HTTP["scheme"] == "http" {{
    $HTTP["host"] =~ ".*" {{
        url.redirect = (".*" => "https://%0$0")
    }}
}}
server.http-parseopts = (
  "header-strict"           => "enable",# default
  "host-strict"             => "enable",# default
  "host-normalize"          => "enable",# default
  "url-normalize-unreserved"=> "enable",# recommended highly
  "url-normalize-required"  => "enable",# recommended
  "url-ctrls-reject"        => "enable",# recommended
  "url-path-2f-decode"      => "enable",# recommended highly (unless breaks app)
  "url-path-dotseg-remove"  => "enable",# recommended highly (unless breaks app)
)

index-file.names            = ( "index.php", "index.html" )
url.access-deny             = ( "~", ".inc" )
static-file.exclude-extensions = ( ".php", ".pl", ".fcgi" )

# include_shell "/usr/share/lighttpd/use-ipv6.pl " + server.port
include_shell "/usr/share/lighttpd/create-mime.conf.pl"
include "/etc/lighttpd/conf-enabled/*.conf"

server.modules += (
		"mod_dirlisting",
		"mod_staticfile",
		"mod_openssl",
)
"""
	#endregion

def pi_dnsmasq_custom(node: Node):
	if node is None:
		LOGGER.error(f"No node in pi_dnsmasq_custom")
		return ""
	if node.oob_interface is None:
		LOGGER.error(f"No OOB interface for {node.hostname} pi hole")
		return ""
	
	#################### TODO: No Hardcoded interface
	#region return string
	return f"""
listen-address=127.0.0.1
listen-address={node.oob_interface.ipv4_address}
listen-address={node.get_interface("ethernet","eth1").ipv4_address}
listen-address=0.0.0.0
"""
	#endregion

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
