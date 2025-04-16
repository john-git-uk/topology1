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

def commands_packages_pi_hole(node):
	#region docstring
	'''
	Provides commands for Debian based systems for installing the packages required for providing DNS services using pi hole.
	'''
	#endregion

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

def commands_config_pi_hole(node):
	#region docstring
	'''
	Provides commands for Debian based systems for configuring DNS services using pi hole.
	'''
	#endregion
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
