from __future__ import annotations
import paramiko
from handle_debian import *
import logging
from convert import get_escaped_string, get_chunky_hex, base64_encode_string
from interface import Interface
from node import Node
from handle_proxmox import Container, execute_proxnode_commands, start_container, wait_for_container_ping_debian, wait_for_container_running
import aiohttp
import asyncio
import pihole as ph
import base64
import time
LOGGER = logging.getLogger('my_logger')
def dns_server_1_structures(topology: Topology):
	from machine_data import get_machine_data

	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	dns_server1_i1 = Interface(
		name="eth0",
		interface_type="ethernet",
		ipv4_address="192.168.2.229",
		ipv4_cidr=24
	)
	dns_server1_i2 = Interface(
		name="eth1",
		interface_type="ethernet",
		ipv4_address="10.133.60.249",
		ipv4_cidr=24
	)
	dns_server1 = Node(
		hostname="dns-server-1",
		machine_data=get_machine_data("debian"),
		oob_interface=dns_server1_i1,
		local_user="root",
		local_password="12345",
		hypervisor_telnet_port=0,
	)
	dns_server1_container = Container(
		ctid=203,
		template="local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
		memory=512,
		cores=1,
		rootfs="local:8",
		resource_pool = "default",
		disk_size=8,
		node_a_part_of=prox1,
		node_data=dns_server1,
	)
	dns_server1.add_interface(dns_server1_i1)
	dns_server1.add_interface(dns_server1_i2)
	prox1.topology_a_part_of.add_node(dns_server1)
	prox1.add_container(dns_server1_container)

def dns_server_1_relations(topology: Topology):
	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

	dns_server_1 = None
	dns_server_1 = topology.get_node("dns-server-1")
	
	if(dns_server_1 is None):
		raise Exception("dns_server_1 is None")

	dns_server_1.get_interface("ethernet","eth0").connect_to(prox1.get_interface("bridge","oob_hitch"))
	dns_server_1.get_interface("ethernet","eth1").connect_to(prox1.get_interface("bridge","vmbr60"))

def dns_server_1_config(dns_server_1: Node):
	prox1 = None
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")

def packages_time_dns_server_1(dns_server_1: Node):
	topology = None
	prox1 = None
	container = None
	topology = dns_server_1.topology_a_part_of
	if topology is None:
		LOGGER.error("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		LOGGER.error("prox1 does not exist! Did you try to load in the wrong order?")
		return
	container = prox1.get_container(dns_server_1.hostname)
	if container is None:
		LOGGER.error("container is None")
		return
	if prox1 is None:
		LOGGER.error("prox1 does not exist! Did you try to load in the wrong order?")
		return
	if len(topology.dns_upstream) == 0:
		LOGGER.error(f"topology.dns_upstream is empty. Configuring {dns_server_1.hostname} requires at least one upstream DNS server")
		return
	if not wait_for_container_running(prox1, container, 30):
		LOGGER.error(f"Container {dns_server_1.hostname} did not start in time")
		return
	commands = []
	for upstream in topology.dns_upstream:
		commands += [
			"rm -rf /etc/resolv.conf",
			f"echo 'nameserver {str(upstream)}' >> /etc/resolv.conf",
		]
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands)
	if not wait_for_container_ping_debian(prox1, container, 30):
		LOGGER.error(f"Container {dns_server_1.hostname} cannot contact debian.org")
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
		'env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends xxd telnet curl openssh-client'
		+' openssh-server nano vim-tiny iputils-ping build-essential '
		+' net-tools iproute2 rsyslog wget '
		+' sudo lighttpd-mod-openssl',
	]
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands)
	commands = []
	commands += [
		"mkdir -p /etc/pihole/",
		"rm -f /etc/pihole/setupVars.conf",
		"touch /etc/pihole/setupVars.conf",
		"wget -O basic-install.sh https://install.pi-hole.net",

		f"echo 'PIHOLE_INTERFACE={dns_server_1.get_interface("ethernet",'eth1').name}' >> /etc/pihole/setupVars.conf",
		f"echo 'IPV4_ADDRESS={dns_server_1.get_interface("ethernet",'eth1').ipv4_address}/"
		+f"{dns_server_1.get_interface("ethernet",'eth1').ipv4_cidr}' >> /etc/pihole/setupVars.conf",
		"echo 'QUERY_LOGGING=false' >> /etc/pihole/setupVars.conf",
		"echo 'INSTALL_WEB_SERVER=true' >> /etc/pihole/setupVars.conf",
		"echo 'WEBPASSWORD=12345' >> /etc/pihole/setupVars.conf",
		f"echo 'PIHOLE_DNS_1={str(topology.dns_upstream[0])}' >> /etc/pihole/setupVars.conf",
		"PIHOLE_SKIP_OS_CHECK=true bash basic-install.sh --unattended"
	]
	if len(topology.dns_upstream) > 1:
		commands += [f"echo 'PIHOLE_DNS_2={str(topology.dns_upstream[1])}' >> /etc/pihole/setupVars.conf"]
	if len(topology.dns_upstream) > 2:
		commands += [f"echo 'PIHOLE_DNS_3={str(topology.dns_upstream[2])}' >> /etc/pihole/setupVars.conf"]
	if len(topology.dns_upstream) > 3:
		commands += [f"echo 'PIHOLE_DNS_4={str(topology.dns_upstream[3])}' >> /etc/pihole/setupVars.conf"]
	if len(topology.dns_upstream) > 4:
		LOGGER.warning(f"Only 4 upstream DNS servers are used in the code, but {len(topology.dns_upstream)} were provided when configuring {dns_server_1.hostname} pi hole upstream")
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands)

def configure_dns_server_1(dns_server_1: Node):
	topology = None
	prox1 = None
	container = None
	topology = dns_server_1.topology_a_part_of
	if topology is None:
		raise ValueError("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	container = prox1.get_container(dns_server_1.hostname)
	if container is None:
		raise ValueError("container is None")
	if prox1 is None:
		raise ValueError("prox1 does not exist! Did you try to load in the wrong order?")
	
	cert_string = ("openssl req -x509 -newkey rsa:2048 -keyout /etc/ssl/private/lighttpd.key -out" 
	f" /etc/ssl/certs/lighttpd.pem -days 365 -nodes -subj '/C=UK/ST=State/L=City/O=Organization/OU=OrgUnit/CN={topology.domain_name_a}.{topology.domain_name_b}'"
	)
	commands = []
	commands += [
		f'echo {base64_encode_string(pi_lighttpd_conf(dns_server_1))} | base64 -d > /etc/lighttpd/lighttpd.conf',
		"mkdir -p /etc/ssl/certs /etc/ssl/private",
		f'echo {base64_encode_string(cert_string)} | base64 -d | sh',
		"rm -f /etc/dnsmasq.d/custom.conf",
		"mkdir -p /etc/dnsmasq.d",
		"touch /etc/dnsmasq.d/custom.conf",
		"chmod 644 /etc/dnsmasq.d/custom.conf",
		f'echo {base64_encode_string(pi_dnsmasq_custom(dns_server_1))} | base64 -d > /etc/dnsmasq.d/custom.conf',
		"/usr/local/bin/pihole logging on",
		"systemctl restart lighttpd",
		"systemctl restart pihole-FTL",
	]
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands)
	time.sleep(1)

	commands = [
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
		# Check for loopback interfaces and (use the first in the list?) TODO
		if main_interface is None:
			for i in range(node.get_interface_count()-1):
				interface = node.get_interface_no(i)
				if interface.ipv4_address is None:
					continue
				if interface.interface_type == "loopback":
					main_interface = interface
					break
		# Check for VLAN 30 SVI
		if main_interface is None:
			for i in range(node.get_interface_count()-1):
				interface = node.get_interface_no(i)
				if interface.ipv4_address is None:
					continue
				if interface.name == "30" and interface.interface_type == "vlan":
					main_interface = interface
					break
		if main_interface is None:
			LOGGER.warning(f"Could not find main interface for {node.hostname} DNS entry")
			continue
		commands += [
			f'echo {base64_encode_string(
				f'echo "address=/{node.hostname}.{topology.domain_name_a}.{topology.domain_name_b}/{main_interface.ipv4_address}" >> /etc/dnsmasq.d/local.conf'
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
	output,error = execute_proxnode_commands(prox1, dns_server_1, commands)

def pi_lighttpd_conf(dns_server_1: Node):
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

#$SERVER["socket"] == "{dns_server_1.oob_interface.ipv4_address}:8443" {{
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

def pi_dnsmasq_custom(dns_server_1: Node):
	#region return string
	return f"""
listen-address=127.0.0.1
listen-address={dns_server_1.oob_interface.ipv4_address}
listen-address={dns_server_1.get_interface("ethernet","eth1").ipv4_address}
listen-address=0.0.0.0
"""
	#endregion
def pi_hole_get_api_key(prox1, dns_server_1):
	# TODO: Error handling
	output,error = execute_proxnode_commands(prox1, dns_server_1, ['cat /etc/pihole/setupVars.conf | grep WEBPASSWORD'])
	for line in output:
		if "WEBPASSWORD" in line:
			return line.split('=')[1]
	raise ValueError("WEBPASSWORD not found in output")