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
from handle_debian.handle_debian import push_file_base64_commands, push_file_hex_commands, base64_encode_bash, base64_encode_string

def proxmox_check_for_wildfly_cli(node): # TODO: Make this use paramiko instead!
	''' 
	Checks if wildfly cli is available to proxmox node

	Returns:
	bool: Availability
	None: Error
	'''
	from handle_proxmox import Container, execute_proxnode_commands
	topology = None
	topology = node.topology_a_part_of
	if topology is None:
		LOGGER.error("topology is None")
	prox1 = topology.get_node("prox1")
	if prox1 is None:
		LOGGER.error("prox1 does not exist! Did you try to load in the wrong order?")
		return
	container = prox1.get_container(node.hostname)
	if container is None:
		LOGGER.error("container is None")
		return
	####################################
	commands = []
	commands.append(base64_encode_bash("/opt/wildfly/bin/jboss-cli.sh --connect ':read-attribute(name=server-state)'"))
	output,error = execute_proxnode_commands(prox1, node, commands)
	for outputx in output:
		if re.search(r'"?outcome"?\s*=>\s*"?success"?', outputx):
			return True
	return False

def commands_config_pki_1(node):
	commands = []
	#ca_dir = '/etc/ssl/ca_config'
	
	#openssl_cnf = '''
	#'''
	#mkdir
	#commands.append('sudo mkdir -p'+ ca_dir + '/' + "{certs,crl,newcerts,private}")
	#commands.append(f'sudo chmod 700 {ca_dir}/private')
	#commands.append(f'sudo touch {ca_dir}/index.txt')
	#commands.append(f'echo 1000 | sudo tee {ca_dir}/serial')
	#commands.append('mkdir -p /etc/wildfly')

	# Packages
	# commands.append('apt-get update')
	# mariadb-plugin-connect-jdbc is not a bookworm package
	# openjdk-17-jdk needed as headless cant generate docs apparently
	commands.append('apt-get install -y openjdk-17-jdk')
	commands.append('apt-get install -y ant')
	commands.append('apt-get install -y mariadb-server')
	commands.append('apt-get install -y mariadb-plugin-connect')
	commands.append('apt-get install -y unzip')

	# Install
	commands.append(
		'unzip -o /root/wildfly-34.0.1.Final-src.zip -d /opt/wildflytmp 1>/dev/null;'
		+ ' rm -f /root/wildfly-34.0.1.Final-src.zip;'
		+ ' unzip -o /root/ejbca-ce-r9.0.0.zip -d /opt/ejbcatmp 1>/dev/null;'
		+ ' rm -f /root/ejbca-ce-r9.0.0.zip;'
		+ ' rm -rf /opt/wildfly;'
		+ ' mkdir -p /opt/wildfly;'
		+ ' rm -rf /opt/ejbca;'
		+ ' mkdir -p /opt/ejbca;'
		+ ' mv /opt/wildflytmp/wildfly-34.0.1.Final/* /opt/wildfly/ || true;'
		+ ' mv /opt/wildflytmp/wildfly-34.0.1.Final/.[!.]* /opt/wildfly/ || true;'
		+ ' rm -rf /opt/wildflytmp;'
		+ ' mv /opt/ejbcatmp/ejbca-ce-r9.0.0/* /opt/ejbca/ || true;'
		+ ' mv /opt/ejbcatmp/ejbca-ce-r9.0.0/.[!.]* /opt/ejbca/ || true;'
		+ ' rm -rf /opt/ejbcatmp;'
	)
	commands.append('adduser --system --no-create-home --group wildfly; chown -R wildfly:wildfly /opt/wildfly')
	#region string
	commands.append('''cat <<EOF > /etc/systemd/system/wildfly.service
[Unit]
Description=WildFly Application Server
After=network.target

[Service]
User=wildfly
Group=wildfly
ExecStart=/opt/wildfly/bin/standalone.sh -b=0.0.0.0
ExecStop=/opt/wildfly/bin/jboss-cli.sh --connect command=:shutdown
Restart=on-failure
Environment=JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
Environment=JBOSS_HOME=/opt/wildfly

[Install]
WantedBy=multi-user.target
EOF
''')
	#endregion

	# Create Database
	#region string
	#DROP DATABASE ejbca;
	commands.append('''mysql -u root -p'root_password' <<EOF
CREATE DATABASE ejbca CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'ejbca'@'localhost' IDENTIFIED BY 'ejbca';
GRANT ALL PRIVILEGES ON ejbca.* TO 'ejbca'@'localhost';
FLUSH PRIVILEGES;
EOF''')
	#endregion

	# Populate Database
	commands.append(base64_encode_bash("mysql -u root -p'root_password' ejbca < /opt/ejbca/doc/sql-scripts/create-tables-ejbca-mysql.sql"))

	commands.append('; '.join((
		#'rm /opt/ejbca/conf/batchtool.properties.sample',
		'rm -f /opt/ejbca/conf/cesecore.properties.sample',
		'rm -f /opt/ejbca/conf/database.properties.sample',
		#'rm /opt/ejbca/conf/jaxws.properties.sample',
		#'rm /opt/ejbca/conf/ocsp.properties.sample',
		#'rm /opt/ejbca/conf/va.properties.sample',
		#'rm /opt/ejbca/conf/cache.properties.sample',
		#'rm /opt/ejbca/conf/jndi.properties.jboss7',
		'rm -f /opt/ejbca/conf/catoken.properties.sample',
		'rm -f /opt/ejbca/conf/custom.properties.sample',
		'rm -f /opt/ejbca/conf/ejbca.properties.sample',
		#'rm /opt/ejbca/conf/systemtests.properties.sample',
		'rm -f /opt/ejbca/conf/web.properties.sample',
		'rm -f /opt/ejbca/conf/install.properties.sample'
		#'rm /opt/ejbca/conf/mail.properties.sample',
		#'rm /opt/ejbca/conf/va-publisher.properties.sample',
	)))

	# Upload ejbca Config
	commands += (push_file_hex_commands(node, '/opt/ejbca/conf/custom.properties', 755, content_ejbca_custom_properties(node)))	
	commands += (push_file_hex_commands(node, '/opt/ejbca/conf/install.properties', 755, content_ejbca_install_properties(node)))
	commands += (push_file_hex_commands(node, '/opt/ejbca/conf/cesecore.properties', 755, content_ejbca_cesecore_properties(node)))
	commands += (push_file_hex_commands(node, '/opt/ejbca/conf/catoken.properties', 755, content_ejbca_catoken_properties(node)))
	commands += (push_file_hex_commands(node, '/opt/ejbca/conf/ejbca.properties', 755, content_ejbca_ejbca_properties(node)))
	commands += (push_file_hex_commands(node, '/opt/ejbca/conf/web.properties', 755, content_ejbca_web_properties(node)))
	commands += (push_file_hex_commands(node, '/opt/ejbca/conf/database.properties', 755, content_ejbca_database_properties(node)))

	# remove bouncy castle
	commands.append(
		r"""sed -i '/.*org.jboss.resteasy.resteasy-crypto.*/d' /opt/wildfly/modules/system/layers/base/org/jboss/as/jaxrs/main/module.xml;"""
		+ ' rm -rf /opt/wildfly/modules/system/layers/base/org/jboss/resteasy/resteasy-crypto/'
	)

	# /opt/wildfly/bin/standalone.conf
	commands += (push_file_hex_commands(node, '/opt/wildfly/bin/standalone.conf', 755, content_wildfly_standalone_conf(node)))
	
	# Configure WildFly as a Service
	commands.append('; '.join((
		'cp /opt/wildfly/docs/contrib/scripts/systemd/launch.sh /opt/wildfly/bin', 
		'cp /opt/wildfly/docs/contrib/scripts/systemd/wildfly.service /etc/systemd/system',
		'mkdir -p /etc/wildfly',
		'cp /opt/wildfly/docs/contrib/scripts/systemd/wildfly.conf /etc/wildfly',
		'systemctl daemon-reload',
		'useradd -r -s /bin/false wildfly',
		'chown -R wildfly:wildfly /opt/wildfly/'
	)))

	#/opt/wildfly/docs/contrib/scripts/systemd/launch.sh

	#/opt/wildfly/docs/contrib/scripts/systemd/wildfly.service
	
	# Create an Elytron Credential Store
	#/usr/bin/wildfly_pass
	#region string
	commands += (push_file_base64_commands(node, '/usr/bin/wildfly_pass',755,"""#!/bin/sh
echo '$(openssl rand -base64 24)'"""
	))
	#endregion

	# Add database password to Credential Store

	#region Add Database Driver
	commands.append(base64_encode_bash('; '.join((
		'mkdir -p /opt/wildfly/modules/system/layers/base/org/mariadb/main',
		'cp /root/mariadb-java-client-3.4.1.jar /opt/wildfly/modules/system/layers/base/org/mariadb/main/'
	))))
	commands += push_file_base64_commands(node, '/opt/wildfly/modules/system/layers/base/org/mariadb/main/module.xml', 755, content_wildfly_mariadb_module(node))
	#endregion
	commands.append('; '.join(([
		'systemctl daemon-reload',
		'systemctl enable wildfly',
		'systemctl restart wildfly'
	])))
	return commands
	
def commands_config_pki_wildfly_cli(node):
	''' This configuration stage uses the Wildfly CLI to prepare it to deploy ejbca.'''
	commands = []
	# Bind management to all interfaces
	commands.append(base64_encode_bash("/opt/wildfly/bin/jboss-cli.sh --connect --timeout=60000 '/interface=management:write-attribute(name=inet-address, value=0.0.0.0)'"))

	# Add Keystore in p12 format
	# TODO: Secret handling.
	keystore_password = '@helloNo1'
	commands.append(base64_encode_bash('; '.join(([
		'mkdir -p /opt/wildfly/standalone/configuration/keystore',
		'chown wildfly:wildfly /opt/wildfly/standalone/configuration/keystore',
		#''.join([
		#	r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add(path=keystore/credentials, relative-to=jboss.server.config.dir, """,
		#	'type=PKCS12, ',
		#	r"""credential-reference={clear-text=""" + keystore_password + r"}, create=true)'"
		#]),
		''.join([
			r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add(path=keystore/credentials,relative-to=jboss.server.config.dir, """,
			r"""credential-reference={clear-text=""" + keystore_password + r"},implementation-properties={keyStoreType=PKCS12},create=true)'"
		]),
		# TODO: This is necessary for https to function. But why is it not using the other keystore?
		''.join([
			'keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 365 ',
			'-keystore /opt/wildfly/standalone/configuration/application.keystore ',
			f'-storepass password -keypass password ', # It's alot of work to change this password.
			'-dname "CN=ca-server-1, O=tapeitup.private, C=GB"'
		]),
	# keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 365 -keystore /opt/wildfly/standalone/configuration/application.keystore -storepass @helloNo1 -keypass @helloNo1 -dname "CN=ca-server-1, O=tapeitup.private, C=GB
		'chown wildfly:wildfly /usr/bin/wildfly_pass',
		'chmod 700 /usr/bin/wildfly_pass'
	]))))

	commands.append(base64_encode_bash(
		'/opt/wildfly/bin/jboss-cli.sh --connect "/subsystem=datasources/jdbc-driver=mariadb:add(driver-name="mariadb", driver-module-name="org.mariadb", driver-class-name="org.mariadb.jdbc.Driver")"',
	))

	# Add a Datasource with Credential
	commands.append(base64_encode_bash('; '.join((
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=dbPassword, secret-value="ejbca")' """,
		' '.join([
			r"""/opt/wildfly/bin/jboss-cli.sh --connect 'data-source add""",
			r'--name=ejbcads',
			r'--connection-url="jdbc:mysql://127.0.0.1:3306/ejbca?permitMysqlScheme"',
			r'--jndi-name="java:/EjbcaDS"',
			r'--use-ccm=true',
			r'--driver-name="mariadb"',
			r'--driver-class="org.mariadb.jdbc.Driver"',
			r'--user-name="ejbca"',
			r'--credential-reference={store=defaultCS, alias=dbPassword}',
			r'--validate-on-match=true',
			r'--background-validation=false',
			r'--prepared-statements-cache-size=50',
			r'--share-prepared-statements=true',
			r'--min-pool-size=5',
			r'--max-pool-size=150',
			r'--pool-prefill=true',
			r'--transaction-isolation=TRANSACTION_READ_COMMITTED',
			r'--check-valid-connection-sql="select 1"',
			"'"
		]),
		#r"""/opt/wildfly/bin/jboss-cli.sh --connect ':reload'"""
	))))

	# Configure WildFly Remoting
	commands.append(base64_encode_bash('; '.join(([
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=remoting/http-connector=http-remoting-connector:write-attribute(name=connector-ref,value=remoting)' """,
		r""" /opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=remoting:add(port=4447,interface=management)' """,
		r""" /opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/http-listener=remoting:add(socket-binding=remoting,enable-http2=true)' """,
		#r""" /opt/wildfly/bin/jboss-cli.sh --connect ':reload'"""
	]))))
	commands.append('; '.join(([
		#'systemctl restart wildfly',
		'chown -R wildfly:wildfly /opt/ejbca',
		#'cd /opt/ejbca',
		#'./bin/ejbca.sh install',
		#'./bin/ejbca.sh ca init',
		#'./bin/ejbca.sh ra init',
		#'./bin/ejbca.sh deploy',
		#'cd /'
	])))
	# Configure Wildfly Logging
	commands.append(base64_encode_bash('; '.join(([
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.ejbca:add(level=INFO)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.cesecore:add(level=INFO)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=com.keyfactor:add(level=INFO)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.jboss.as.config:write-attribute(name=level, value=WARN)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.jboss:add(level=WARN)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.wildfly:add(level=WARN)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.xnio:add(level=WARN)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.hibernate:add(level=WARN)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.apache.cxf:add(level=WARN)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/logger=org.cesecore.config.ConfigurationHolder:add(level=WARN)'"""
	]))))

	# Remove console logging?
	#/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/root-logger=ROOT:remove-handler(name=CONSOLE)'
	#/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/console-handler=CONSOLE:remove()'

	# Enable Syslog Shipping
	#/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/json-formatter=logstash:add(exception-output-type=formatted, key-overrides=[timestamp="@timestamp"],meta-data=[@version=1])'
	#/opt/wildfly/bin/jboss-cli.sh --connect "/subsystem=logging/syslog-handler=syslog-shipping:add(app-name=EJBCA,enabled=true,facility=local-use-0,hostname=$(hostname -f),level=INFO,named-formatter=logstash,port=514,server-address=syslog.server,syslog-format=RFC5424)"
	#/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=logging/root-logger=ROOT:add-handler(name=syslog-shipping)'

	#Enable Audit Logging To File?

	#Configure OCSP Logging?

	#Remove preconfigured http
	commands.append(base64_encode_bash('; '.join(([
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/http-listener=default:remove()'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=http:remove()'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/https-listener=https:remove()'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=https:remove()'""",
		#r"""/opt/wildfly/bin/jboss-cli.sh --connect ':reload'"""
	]))))

	#Config the three ports
	commands.append(base64_encode_bash('; '.join(([
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/interface=http:add(inet-address="0.0.0.0")'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/interface=httpspub:add(inet-address="0.0.0.0")'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/interface=httpspriv:add(inet-address="0.0.0.0")'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=http:add(port="8080",interface="http")'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=httpspub:add(port="8442",interface="httpspub")'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=httpspriv:add(port="8443",interface="httpspriv")'"""
	]))))
	#

	#Config TLS
	commands.append(base64_encode_bash('; '.join(([
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpskeystorepassword, secret-value="serverpwd")'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpstruststorepassword, secret-value="changeit")'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/key-store=httpsKS:add(path="keystore/keystore.p12",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpskeystorepassword},type=PKCS12)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/key-store=httpsTS:add(path="keystore/truststore.p12",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpstruststorepassword},type=PKCS12)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/key-manager=httpsKM:add(key-store=httpsKS,algorithm="SunX509",credential-reference={store=defaultCS, alias=httpskeystorepassword})'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/trust-manager=httpsTM:add(key-store=httpsTS)'"""
	]))))
	commands.append(base64_encode_bash(''.join(([
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/server-ssl-context=httpspub:add(key-manager=httpsKM,protocols=["TLSv1.3","TLSv1.2"],""",
		r"""use-cipher-suites-order=false,cipher-suite-filter="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,""",
		r"""TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",cipher-suite-names="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")'"""
	]))))
	commands.append(base64_encode_bash(''.join(([
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=elytron/server-ssl-context=httpspriv:add(key-manager=httpsKM,protocols=["TLSv1.3","TLSv1.2"],""",
		r"""use-cipher-suites-order=false,cipher-suite-filter="TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,""",
		r"""TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",cipher-suite-names="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",trust-manager=httpsTM,need-client-auth=true)'"""
	]))))

	#Add HTTP(S) Listeners
	commands.append(base64_encode_bash('; '.join(([
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/http-listener=http:add(socket-binding="http", redirect-socket="httpspriv")'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/https-listener=httpspub:add(socket-binding="httpspub", ssl-context="httpspub", max-parameters=2048)'""",
		r"""/opt/wildfly/bin/jboss-cli.sh --connect '/subsystem=undertow/server=default-server/https-listener=httpspriv:add(socket-binding="httpspriv", ssl-context="httpspriv", max-parameters=2048)'""",
		#r"""/opt/wildfly/bin/jboss-cli.sh --connect ':reload'"""
	]))))

	# TODO: Secret
	# Add user to access wildfly web gui
	# --silent ?
	wildfly_user_web = 'admin'
	wildfly_pass_web = 'nimda'
	# /opt/wildfly/bin/add-user.sh --user admin --password 'nimda' --realm ManagementRealm 
	commands.append(base64_encode_bash(f"/opt/wildfly/bin/add-user.sh --user {wildfly_user_web} --password '{wildfly_pass_web}' --realm ManagementRealm"))
	
	# Rebind the Management Web Interface to OOB
	# TODO: This is old and I dont think it works.
	commands.append(base64_encode_bash('; '.join(([
		#"/opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/"
		#+ "socket-binding=management-http:write-attribute(name=inet-address, value="+str(node.oob_interface.ipv4_address)+")'",
		"/opt/wildfly/bin/jboss-cli.sh --connect '/interface=management:write-attribute(name=inet-address, value=0.0.0.0)'",
		"/opt/wildfly/bin/jboss-cli.sh --connect '/interface=public:write-attribute(name=inet-address, value=0.0.0.0)'"
	]))))

	# Compile 
	debug_manual_deployment = False
	if debug_manual_deployment == False:
		commands.append(base64_encode_bash('echo "export APPSRV_HOME=/opt/wildfly" >> ~/.bashrc; source ~/.bashrc'))
		commands.append(base64_encode_bash('; '.join(([
			'echo "export APPSRV_HOME=/opt/wildfly" >> ~/.bashrc; source ~/.bashrc',
			'cd /opt/ejbca',
			'ant -q clean deployear',
			'sleep 1',
			'systemctl stop wildfly',
			'sleep 4',
			'systemctl start wildfly',
			'cd /'
		]))))
	#region comment_code reference for manual deployment
	'''
	echo "export APPSRV_HOME=/opt/wildfly" >> ~/.bashrc; source ~/.bashrc

	cd /opt/ejbca

	ant -q clean deployear

	systemctl stop wildfly

	sleep 4

	systemctl start wildfly
	'''
	#endregion

	# /opt/wildfly/bin/jboss-cli.sh --connect '/socket-binding-group=standard-sockets/socket-binding=management-http:write-attribute(name=inet-address, value=0.0.0.0)'

	#Configure the Firewall
	#Open port 8080, 8442 and 8443 for incoming TCP traffic.
	#Not implemented

	#Use an HSM for TLS?

	#commands.append('systemctl restart wildfly')

	LOGGER.debug(f"commands_config_pki_ca:")
	print('')
	for command in commands:
		print(command)

	return commands

def commands_config_pki_ejbca_install(node):
	'''docstring'''
	#region debug_commands
	'''
cd /opt/ejbca

ant runinstall

ant deploy-keystore

chown -R wildfly:wildfly /opt/wildfly/standalone/configuration/keystore/

chmod -R 755 /opt/wildfly/standalone/configuration/keystore/

systemctl stop wildfly

sleep 4

systemctl start wildfly

cd /
'''
	#endregion

	#######################

	commands = []

	#######################

	#debug_manual_install = True
	debug_manual_install = False
	if debug_manual_install == False:
		commands.append('; '.join(([
			'cd /opt/ejbca',
			'ant runinstall',
			'ant deploy-keystore',
			'chown -R wildfly:wildfly /opt/wildfly/standalone/configuration/keystore/',
			'chmod -R 755 /opt/wildfly/standalone/configuration/keystore/',
			'systemctl stop wildfly',
			'sleep 4',
			'systemctl start wildfly',
			'cd /'
		])))
	
	#######################

	return commands

def commands_config_pki_recreate_local_admin(node):
	'''Recreate the identity + crypto for 'Local Admin' that can be used to access the ejbca web interface from the OOB interface.'''

	# /opt/ejbca/bin/ejbca.sh ra addendentity --username local_admin --dn "CN=Local Admin, O=tapeitup.private, C=GB" --caname ca.ca-server-1 --type 1 --password local_nimda --token "USERGENERATED" --verbose

	# /opt/ejbca/bin/ejbca.sh createcert --username local_admin --password local_nimda -c /root/local_admin.csr -f /root/local_admin.crt --verbose

	# /opt/ejbca/bin/ejbca.sh ra revokecert --dn "CN=ca.ca-server-1,O=tapeituptapeitup,C=GB" -s SERIAL -r 1 --verbose
	
	commands = []
	topology = node.topology_a_part_of
	local_admin_password = 'local_nimda'

	serial = paramiko_find_serial_by_subject(node, 'Local Admin')

	commands.append('cd /opt/ejbca')

	if serial is not None:
		plain3 = (' '.join([
			'/opt/ejbca/bin/ejbca.sh ra revokecert',
			f'--dn "CN=ca.{node.hostname},O={topology.domain_name_a}.{topology.domain_name_b},C=GB',
			f'-s {serial}',
			'--verbose'
		]))
		commands.append(base64_encode_bash(plain3))

	# Generates ERROR if already exists.
	# ERROR: User 'local_admin' already exists in the database.
	plain1 = (' '.join([
		'/opt/ejbca/bin/ejbca.sh ra addendentity --username local_admin',
		f'--dn "CN=Local Admin, O={topology.domain_name_a}.{topology.domain_name_b}, C=GB"',
		f'--caname ca.{node.hostname}',
		'--type 1',
		f'--password {local_admin_password}',
		'--token "USERGENERATED"',
		'--verbose'
	]))
	commands.append(base64_encode_bash(plain1))

	plain2 = (' '.join([
		'/opt/ejbca/bin/ejbca.sh createcert --username local_admin',
		f'--password {local_admin_password}',
		'-c /root/local_admin.csr',
		'-f /root/local_admin.crt',
		'--verbose'
	]))
	commands.append(base64_encode_bash(plain2))

	# TODO: Consider duplicate entries on rerun
	plain4 = (' '.join([
	'/opt/ejbca/bin/ejbca.sh roles addrolemember --role "Super Administrator Role"',
	'--caname ca.ca-server-1',
	'--value "Local Admin"',
	'--with CertificateAuthenticationToken:WITH_COMMONNAME',
	'--verbose'
	]))
	commands.append(base64_encode_bash(plain4))
	# bash ejbca.sh roles addrolemember --role "Super Administrator Role" --caname ca.ca-server-1 
	# --value "Local Admin" --with CertificateAuthenticationToken:WITH_COMMONNAME

	commands.append('cd /')

	return commands

def generate_local_certificate(ca_server: Node):
	from cryptography import x509
	from cryptography.x509.oid import NameOID
	from cryptography.hazmat.primitives.asymmetric import rsa
	from cryptography.hazmat.primitives import serialization, hashes
	from cryptography.hazmat.backends import default_backend

	if ca_server.machine_data.name != 'debian':
		LOGGER.critical('generate_local_certificate passed non debian node')
		exit()

	try:
		topology = ca_server.topology_a_part_of
	except Exception as e:
		LOGGER.critical('generate_local_certificate passed node not connected to a topology')
		LOGGER.debug(e)
		exit()
	
	# Generate a 2048-bit RSA private key
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)

	# Save the private key to a PEM file
	out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "pki"
	out_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(out_path,'local_admin.key'), "wb") as key_file:
		key_file.write(
			private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption()
			)
		)

	# Build a subject for the CSR
	subject = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, "LocalAdmin"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, f'{topology.domain_name_a}.{topology.domain_name_b}'),
		x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
	])

	# Create the CSR using the private key
	csr = x509.CertificateSigningRequestBuilder().subject_name(
		subject
	).sign(private_key, hashes.SHA256(), default_backend())

	# Save the CSR to a PEM file
	out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "pki"
	out_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(out_path,'local_admin.csr'), "wb") as csr_file:
		csr_file.write(csr.public_bytes(serialization.Encoding.PEM))

def generate_local_p12(ca_server: Node):
	'''Generate a p12 that browsers can import for the local_admin that has full access to CA Server.'''
	from cryptography import x509
	from cryptography.hazmat.primitives import serialization
	from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption, NoEncryption
	from cryptography.hazmat.backends import default_backend

	key_path = str(os.path.join(GLOBALS.app_path.parent, 'output', 'pki', 'local_admin.key'))
	cert_path = str(os.path.join(GLOBALS.app_path.parent, 'output', 'pki', 'local_admin.crt'))
	p12_path = str(os.path.join(GLOBALS.app_path.parent, 'output', 'pki', 'local_admin.p12'))
	ca_path = str(os.path.join(GLOBALS.app_path.parent, 'output', 'pki', f'ca.{ca_server.hostname}.crt'))

	# Load private_key
	with open(key_path, "rb") as key_file:
		private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)
	# Serialize the private key to an unencrypted PEM format
	unencrypted_private_key = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=NoEncryption()  # No encryption for the private key
	)

	# Load certificate
	with open(cert_path, "rb") as cert_file:
		certificate = x509.load_pem_x509_certificate(
			cert_file.read(),
			backend=default_backend()
		)

	# Load CA certificate
	with open(ca_path, "rb") as ca_file:
		ca_certificate = x509.load_pem_x509_certificate(
		ca_file.read(),
		backend=default_backend()
	)
	ca_certificates = [ca_certificate]

	p12_data = pkcs12.serialize_key_and_certificates(
		name='Local Admin'.encode(),
		key=unencrypted_private_key,
		cert=certificate,
		cas=ca_certificates,
		encryption_algorithm=NoEncryption()#BestAvailableEncryption(b'trec')
	)

	# Write P12 data to output file
	with open(p12_path, "wb") as p12_file:
		p12_file.write(p12_data)

def paramiko_retrieve_local_cert(ca_server: Node):
	''' retrieves the local admin cert from ca_server'''
	cert_name = 'local_admin.crt'
	cert_source = str(Path('/root') / cert_name)
	cert_dest = str(GLOBALS.app_path.parent / 'output' / 'pki' / cert_name)

	ssh_client = ca_server.paramiko_get_connection()

	from scp import SCPClient
	scp_client = SCPClient(ssh_client.get_transport())
	scp_client.get(cert_source, cert_dest)
	scp_client.close()

def paramiko_retrieve_ejbca_cert(ca_server: Node, cert_name: str = ''):
	'''Retrieves the cert of the ca_server.'''
	if len(cert_name) == 0:
		return None
	org = f'{ca_server.topology_a_part_of.domain_name_a}.{ca_server.topology_a_part_of.domain_name_b}'
	serial = paramiko_find_serial_by_subject(ca_server, f'ca.{ca_server.hostname}', org)

	cert_source = str(Path('/root') / f'{cert_name}.crt')
	cert_dest = str(GLOBALS.app_path.parent / 'output' / 'pki' / f'{cert_name}.crt')

	ssh_client = ca_server.paramiko_get_connection()

	ca_server.paramiko_execute_command(f'/opt/ejbca/bin/ejbca.sh ca getcacert {cert_name} -f {cert_source}')

	from scp import SCPClient
	scp_client = SCPClient(ssh_client.get_transport())
	scp_client.get(cert_source, cert_dest)
	scp_client.close()

def paramiko_find_serial_by_subject(ca_server: Node, common_name: str, organization: str = None):
	"""
	Contacts ca-server then parses certificate for a serial matching the given info.

	Returns:
	  str or None: The serial number if a matching subjectDN is found, otherwise None.
	"""
	if organization is None:
		organization = str(f'{ca_server.topology_a_part_of.domain_name_a}.{ca_server.topology_a_part_of.domain_name_b}')

	stdout_txt, stderr_txt = ca_server.paramiko_execute_command(f'/opt/ejbca/bin/ejbca.sh ca listexpired 99999')
	text = stdout_txt + stderr_txt

	subject_query = f'CN={common_name},O={organization},C=GB'
	
	pattern = r"Certificate with subjectDN '([^']+)' and serialNumber '([^']+)' expires at"
	matches = re.findall(pattern, text)
	for subject, serial in matches:
		if subject_query in subject:
			return serial
	return None

def paramiko_upload_pki_assets(node: Node):
	''' Uploads a number of files to the node that are required. The files are from the assets section of the project.'''
	import os
	import platform
	import sys
	# TODO: Only runs on Linux for now
	if platform.system() != "Linux":
		raise OSError("This script must be run on a Linux system.")

	# Mariadb Connector
	#connector_dir = os.path.join(GLOBALS.app_path.parent, 'assets', 'mariadb-java-client-3.4.1.jar' )
	#connector_url = 'https://dlm.mariadb.com/3852266/Connectors/java/connector-java-3.4.1/mariadb-java-client-3.4.1.jar'

	# Wildfly Java App Server
	wildfly_dir = os.path.join(GLOBALS.app_path.parent, 'assets', 'wildfly-34.0.1.Final-src.zip' )
	wildfly_url = 'https://github.com/wildfly/wildfly/releases/download/34.0.1.Final/wildfly-34.0.1.Final.zip'
	# /root/wildfly-34.0.1.Final-src.zip
	wildfly_dest = os.path.join('/root', 'wildfly-34.0.1.Final-src.zip')

	# Ejbca The PKI CA
	ejbca_dir = os.path.join(GLOBALS.app_path.parent, 'assets', 'ejbca-ce-r9.0.0.zip' )
	ejbca_dest = os.path.join('/root', 'ejbca-ce-r9.0.0.zip')
	ejbca_url = 'https://codeload.github.com/Keyfactor/ejbca-ce/zip/refs/tags/r8.3.2'

	# The mariaDB connector module
	module_dir = os.path.join(GLOBALS.app_path.parent, 'assets', 'mariadb-java-client-3.4.1.jar' )
	module_dest = os.path.join('/root', 'mariadb-java-client-3.4.1.jar')
	module_url = ''

	# local_admin.csr
	csr_dir = os.path.join(GLOBALS.app_path.parent, 'output', 'pki', 'local_admin.csr' )
	csr_dest = os.path.join('/root', 'local_admin.csr')

	# Check if files exist
	if not os.path.exists(wildfly_dir):
		LOGGER.info(f'Wildfly zip file does not exist at {wildfly_dir}. Downloading...')
		
		# Download
		import requests
		response = requests.get(wildfly_url)
		with open(wildfly_dir, 'wb') as f:
			f.write(response.content)
			# calculate the remaining bytes
			remaining_bytes = int(response.headers.get('Content-Length', 0))
			LOGGER.info(f'Downloading {remaining_bytes} bytes...')
			# update the progress bar
			#progress_bar = tqdm(total=remaining_bytes, unit='B', unit_scale=True, desc='Downloading')
			#for data in response.iter_content(chunk_size=1024):
			#	progress_bar.update(len(data))
			

		response = requests

	if not os.path.exists(ejbca_dir):
		LOGGER.info(f'EJBCA zip file does not exist at {ejbca_dir}. Downloading...')

		# Download
		import requests
		response = requests.get(ejbca_url)
		with open(ejbca_dir, 'wb') as f:
			f.write(response.content)
		
		response = requests

	if not os.path.exists(module_dir):
		raise OSError (f'MariaDB module jar file does not exist at {module_dir}.')

	if not os.path.exists(csr_dir):
		raise OSError (f'LocalAdmin certificate signing request file does not exist at {module_dir}.')

	ssh_client = node.paramiko_get_connection()

	from scp import SCPClient
	scp_client = SCPClient(ssh_client.get_transport())
	scp_client.put(str(wildfly_dir), str(wildfly_dest))
	scp_client.put(str(ejbca_dir), str(ejbca_dest))
	scp_client.put(str(module_dir), str(module_dest))
	scp_client.put(str(csr_dir), str(csr_dest))
	scp_client.close()

def paramiko_check_for_wildfly_cli(node):
	''' 
	Checks if wildfly cli is available.

	Returns:
	bool: Availability
	None: Error
	'''
	topology = None
	topology = node.topology_a_part_of
	if topology is None:
		LOGGER.error("topology is None")
	####################################

	stdout_txt, stderr_txt = node.paramiko_execute_command("/opt/wildfly/bin/jboss-cli.sh --connect ':read-attribute(name=server-state)'")
	text = stdout_txt + stderr_txt

	if re.search(r'"?outcome"?\s*=>\s*"?success"?', text):
		return True
	return False

def content_ejbca_install_properties(node: Node):
	#region string
	return f'''ca.name=ca.{node.hostname}
ca.dn=CN=ca.{node.hostname},O={node.topology_a_part_of.domain_name_a}.{node.topology_a_part_of.domain_name_b},C=GB
ca.tokentype=soft
#ca.tokenproperties=/opt/ejbca/conf/catoken.properties
ca.tokenpassword=insecure_password
ca.keytype=RSA
ca.keyspec=2048
ca.signaturealgorithm=SHA256WithRSA
ca.validity=3650
ca.policy=null
ca.certificateprofile=ROOTCA
'''
	#endregion

def content_ejbca_cesecore_properties(node: Node):
	#region string
	return f'''allow.external-dynamic.configuration=false
password.encryption.key=AAA
ca.rngalgorithm=SHA1PRNG
ca.serialnumberoctetsize=20
certificate.validityoffset=-10m
custom.class.whitelist
database.crlgenfetchordered=false
securityeventsaudit.implementation.0=org.cesecore.audit.impl.log4j.Log4jDevice
securityeventsaudit.implementation.1=org.cesecore.audit.impl.integrityprotected.IntegrityProtectedDevice
securityeventsaudit.exporter.1=org.cesecore.audit.impl.AuditExporterXml
intresources.preferredlanguage=en
intresources.secondarylanguage=en
cryptotoken.keystorecache=true
db.keepinternalcakeystores=true
ca.keepocspextendedservice=true
keystore.use_legacy_pkcs12 = true
'''
	#endregion

def content_ejbca_ejbca_properties(node: Node):
	# TODO: This belongs as global secrets
	#region string
	appserv_home = '/opt/wildfly'
	return f'''ejbca.cli.defaultusername=ejbca
ejbca.cli.defaultpassword=ejbca
appserver.home={appserv_home}
ejbca.productionmode=false
allow.external-dynamic.configuration=false
'''
	#endregion

def content_ejbca_web_properties(node: Node):
	# TODO: This belongs as global secrets
	# TODO: Double check the special characters
	#region string
	superadmin_cn = 'SuperAdmin'
	forward = 'ejbca-web.'
	https_server_hostname = forward + node.hostname
	return f'''java.trustpassword=changeit
superadmin.cn={superadmin_cn}
superadmin.dn=CN={superadmin_cn},O={node.topology_a_part_of.domain_name_a}.{node.topology_a_part_of.domain_name_b},C=GB
superadmin.password=ejbca
superadmin.batch=true
superadmin.validity=2y
httpsserver.password=serverpwd
httpsserver.hostname={https_server_hostname}
httpsserver.dn=CN={forward + node.hostname},O={node.topology_a_part_of.domain_name_a}.{node.topology_a_part_of.domain_name_b},C=GB
httpsserver.an=dnsname={https_server_hostname}
httpserver.pubhttp=8080
httpserver.pubhttps=8442
httpserver.privhttps=8443
httpserver.external.privhttps=8443
httpserver.external.fqdn={https_server_hostname}
httpsserver.bindaddress.pubhttp=0.0.0.0
httpsserver.bindaddress.pubhttps=0.0.0.0
httpsserver.bindaddress.privhttps=0.0.0.0
httpsserver.tokentype=P12
web.reqcertindb=true
ejbca.cli.defaultusername=ejbca
ejbca.cli.defaultpassword=ejbca
'''
	#endregion

def content_ejbca_database_properties(node: Node):
	# TODO: This belongs as global secrets
	#region string
	return f'''datasource.jndi-name=EjbcaDS
database.name=mysql
database.useSeparateCertificateTable=false
database.url=jdbc:mysql://127.0.0.1:3306/ejbca?characterEncoding=UTF-8
database.driver=org.mariadb.jdbc.Driver
database.username=ejbca
database.password=ejbca
'''
	#endregion

def content_ejbca_custom_properties(node: Node):
	#region string
	return """noinput=true

# Appserver configuration
appserver.type=jboss
appserver.subtype=jboss7"""
	#endregion

def content_ejbca_catoken_properties(node: Node):
	'''docstring'''
	#region string
	return '''sharedLibrary /opt/utimaco/p11/libcs2_pkcs11.so
slotLabelType=SLOT_NUMBER
slotLabelValue=1

# CA key configuration
defaultKey defaultRoot
certSignKey signRoot
crlSignKey signRoot
testKey testRoot
alternativeCertSignKey alternativeSignRoot'''
	#endregion

def content_wildfly_standalone_conf(node: Node):
	tx_node_id = random.randint(1, 255) #Random value between 1 and 255
	heap_size = 2048
	#region string
	return f'''if [ "x$JBOSS_MODULES_SYSTEM_PKGS" = "x" ]; then
	 JBOSS_MODULES_SYSTEM_PKGS="org.jboss.byteman"
fi

if [ "x$JAVA_OPTS" = "x" ]; then
	 JAVA_OPTS="-Xms{heap_size}m -Xmx{heap_size}m"
	 JAVA_OPTS="$JAVA_OPTS -Dhttps.protocols=TLSv1.2,TLSv1.3"
	 JAVA_OPTS="$JAVA_OPTS -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3"
	 JAVA_OPTS="$JAVA_OPTS -Djava.net.preferIPv4Stack=true"
	 JAVA_OPTS="$JAVA_OPTS -Djboss.modules.system.pkgs=$JBOSS_MODULES_SYSTEM_PKGS"
	 JAVA_OPTS="$JAVA_OPTS -Djava.awt.headless=true"
	 JAVA_OPTS="$JAVA_OPTS -Djboss.tx.node.id={tx_node_id}"
	 JAVA_OPTS="$JAVA_OPTS -XX:+HeapDumpOnOutOfMemoryError"
	 JAVA_OPTS="$JAVA_OPTS -Djdk.tls.ephemeralDHKeySize=2048"
else
	 echo "JAVA_OPTS already set in environment; overriding default settings with values: $JAVA_OPTS"
fi
JAVA_OPTS="$JAVA_OPTS --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED"'''

	#endregion

def content_wildfly_systemd_launch(node: Node):
	#/opt/wildfly/docs/contrib/scripts/systemd/launch.sh
	#region string
	return '''#!/bin/bash
if [ "x$WILDFLY_HOME" = "x" ]; then
	WILDFLY_HOME="/opt/wildfly"
fi
if [[ "$1" == "domain" ]]; then
	$WILDFLY_HOME/bin/domain.sh -c $2 -b $3
else
	$WILDFLY_HOME/bin/standalone.sh -c $2 -b $3
fi'''
	#endregion

def content_wildfly_systemd_service(node: Node):
	#/opt/wildfly/docs/contrib/scripts/systemd/wildfly.service
	#region string
	return '''[Unit]
Description=The WildFly Application Server
After=syslog.target network.target
Before=httpd.service

[Service]
Environment=LAUNCH_JBOSS_IN_BACKGROUND=1
EnvironmentFile=-/etc/wildfly/wildfly.conf
User=wildfly
LimitNOFILE=102642
PIDFile=/run/wildfly/wildfly.pid
ExecStart=/opt/wildfly/bin/launch.sh $WILDFLY_MODE $WILDFLY_CONFIG $WILDFLY_BIND
StandardOutput=null

[Install]
WantedBy=multi-user.target'''
	#endregion

def content_wildfly_systemd_conf(node: Node):
	#/opt/wildfly/docs/contrib/scripts/systemd/wildfly.conf
	#region string
	return '''# The configuration you want to run
WILDFLY_CONFIG=standalone.xml

# The mode you want to run
WILDFLY_MODE=standalone

# The address to bind to
WILDFLY_BIND=0.0.0.0'''
	#endregion

def content_wildfly_mariadb_module(node: Node):
	#region string
	version = 'mariadb-java-client-3.4.1.jar'
	return f"""<?xml version="1.0" ?>
<module xmlns="urn:jboss:module:1.3" name="org.mariadb">
	<resources>
		<resource-root path="{version}"/>
	</resources>
	<dependencies>
		<module name="javax.api"/>
		<module name="javax.transaction.api"/>
	</dependencies>
</module>"""
	#endregion