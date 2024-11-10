import ipaddress
import logging
import libvirt
import os
from pathlib import Path
import configparser
from dotenv import load_dotenv
from convert import input_yes_no
import getpass
VIR_DOMAIN_STATE_LOOKUP = {
	libvirt.VIR_DOMAIN_NOSTATE: 'No State',
	libvirt.VIR_DOMAIN_RUNNING: 'Running',
	libvirt.VIR_DOMAIN_BLOCKED: 'Blocked',
	libvirt.VIR_DOMAIN_PAUSED: 'Paused',
	libvirt.VIR_DOMAIN_SHUTDOWN: 'Shutting Down',
	libvirt.VIR_DOMAIN_SHUTOFF: 'Shut Off',
	libvirt.VIR_DOMAIN_CRASHED: 'Crashed',
	libvirt.VIR_DOMAIN_PMSUSPENDED: 'Power Management Suspended',
}
LOGGER = logging.getLogger('my_logger')
class Globals:
	def __init__(self):
		self.app_path = None
		self.testbed_path = None
		self.hypervisor_ipv4_address = None
		self.hypervisor_ssh_username = None
		self.hypervisor_ssh_password = None
		self.hypervisor_ssh_port = 0
		self.lab_username = None
		self.lab_password = None
		self.telnet_transfer_path = None
		self.init_error_free_path()

		self.r1_username = None
		self.r1_password = None
		self.r1_ca_password = None
		self.ntp_password = None
		self.r2_username = None
		self.r2_password = None
		self.r3_username = None
		self.r3_password = None
		self.sw1_username = None
		self.sw1_password = None
		self.sw2_username = None
		self.sw2_password = None
		self.sw3_username = None
		self.sw3_password = None
		self.sw4_username = None
		self.sw4_password = None
		self.sw5_username = None
		self.sw5_password = None
		self.sw6_username = None
		self.sw6_password = None
		self.sw7_username = None
		self.sw7_password = None
		self.prox1_username = None
		self.prox1_password = None
		self.dns_server_1_username = None
		self.dns_server_1_password = None
		self.dns_web_api_password = None
		self.ldap_server_1_username = None
		self.ldap_server_1_password = None
		self.ldap_password = None
		self.radius_server_1_username = None
		self.radius_server_1_password = None
		self.radius_password = None
		
		self.vpn_passwords = None

	def init_error_free_path(self):
		if(os.path.exists("../main.py")):
			self.app_path = Path(os.path.abspath("../"))
		if(os.path.exists("../src/main.py")):
			self.app_path = Path(os.path.abspath("../src"))
		if(os.path.exists("../python_config/src/main.py")):
			self.app_path = Path(os.path.abspath("../python_config/src"))
		if(os.path.exists("../topology1/python_config/src/main.py")):
			self.app_path = Path(os.path.abspath("../topology1/python_config/src"))
		
		self.testbed_path = self.app_path.parent / 'output'/ 'testbed.yaml'
	def write(self):
		config = configparser.ConfigParser()
		config['General'] = {
			'Telnet_Transfer_Path': self.telnet_transfer_path,
		}
		config['Lab_Hypervisor'] = {
			'IPv4_Address': self.hypervisor_ipv4_address,
			'SSH_User': self.hypervisor_ssh_username,
			'SSH_Password': self.hypervisor_ssh_password,
			'SSH_Port': self.hypervisor_ssh_port,
			'Lab_Username': self.lab_username,
			'Lab_Password': self.lab_password,
		}
		config['Network_Nodes'] = {
			'R1_Username': self.r1_username,
			'R1_Password': self.r1_password,
			'R1_CA_Password': self.r1_ca_password,
			'NTP_Password': self.ntp_password,
			'R2_Username': self.r2_username,
			'R2_Password': self.r2_password,
			'R3_Username': self.r3_username,
			'R3_Password': self.r3_password,
			'SW1_Username': self.sw1_username,
			'SW1_Password': self.sw1_password,
			'SW2_Username': self.sw2_username,
			'SW2_Password': self.sw2_password,
			'SW3_Username': self.sw3_username,
			'SW3_Password': self.sw3_password,
			'SW4_Username': self.sw4_username,
			'SW4_Password': self.sw4_password,
			'SW5_Username': self.sw5_username,
			'SW5_Password': self.sw5_password,
			'SW6_Username': self.sw6_username,
			'SW6_Password': self.sw6_password,
			'SW7_Username': self.sw7_username,
			'SW7_Password': self.sw7_password,
		}
		config['Servers'] = {
			'Prox1_Username': self.prox1_username,
			'Prox1_Password': self.prox1_password,
			'DNS_Server_1_Username': self.dns_server_1_username,
			'DNS_Server_1_Password': self.dns_server_1_password,
			'DNS_Web_API_Password': self.dns_web_api_password,
			'LDAP_Server_1_Username': self.ldap_server_1_username,
			'LDAP_Server_1_Password': self.ldap_server_1_password,
			'LDAP_Password': self.ldap_password,
			'Radius_Server_1_Username': self.radius_server_1_username,
			'Radius_Server_1_Password': self.radius_server_1_password,
			'Radius_Password': self.radius_password,
		}
		with open(f'{self.app_path.parent.parent}/config.ini', 'w') as configfile:
			config.write(configfile)
	def validate_data(self):


		self.telnet_transfer_path = self.secret_prompt('Telnet Transfer Path (Enter Rubbish to Skip)', self.telnet_transfer_path)
		self.hypervisor_ipv4_address = self.ip_prompt('Hypervisor SSH IPv4 address', self.hypervisor_ipv4_address)
		
		# Check hypervisor SSH port is a valid port number
		valid_hypervisor_ssh_port = False
		while not valid_hypervisor_ssh_port:
			try:
				port = int(self.hypervisor_ssh_port)
			except ValueError:
				port = None
			if port < 1 or port > 65535:
				LOGGER.warning("Hypervisor SSH port is not a valid port number.")
				self.hypervisor_ssh_port=input("Enter a valid port number for the hypervisor SSH port: ")
			else:
				if(input_yes_no("Is "+str(self.hypervisor_ssh_port)+" the correct hypervisor SSH port? (y/n): ")):
					valid_hypervisor_ssh_port = True
				else:
					self.hypervisor_ssh_port=input("Enter a valid port number for the hypervisor SSH port: ")

		
		#self.hypervisor_ssh_key = secret_prompt("*Lab Username*",self.hypervisor_ssh_key)
		self.hypervisor_ssh_username = self.secret_prompt("*Hypervisor Username*",self.hypervisor_ssh_username)
		self.hypervisor_ssh_password = self.hidden_secret_prompt("*Hypervisor Password*",self.hypervisor_ssh_password)
		self.lab_username = self.secret_prompt("*Lab Username*",self.lab_username)
		self.lab_password = self.hidden_secret_prompt("*Lab Password*", self.lab_password)
		self.r1_username = self.secret_prompt("*R1 Username*",self.r1_username)
		self.r1_password = self.hidden_secret_prompt("*R1 Password*",self.r1_password)
		self.r1_ca_password = self.hidden_secret_prompt("*R1 Certificate Authority Password*",self.r1_ca_password)
		self.ntp_password = self.hidden_secret_prompt("*NTP Pasword*", self.ntp_password)
		self.r2_username = self.secret_prompt("*R2 Username*",self.r2_username)
		self.r2_password = self.hidden_secret_prompt("*R2 Password*",self.r2_password)
		self.r3_username = self.secret_prompt("*R3 Username*",self.r3_username)
		self.r3_password = self.hidden_secret_prompt("*R3 Password*",self.r3_password)
		self.sw1_username = self.secret_prompt("*SW1 Username*",self.sw1_username)
		self.sw1_password = self.hidden_secret_prompt("*SW1 Password*",self.sw1_password)
		self.sw2_username = self.secret_prompt("*SW2 Username*",self.sw2_username)
		self.sw2_password = self.hidden_secret_prompt("*SW2 Password*",self.sw2_password)
		self.sw3_username = self.secret_prompt("*SW3 Username*",self.sw3_username)
		self.sw3_password = self.hidden_secret_prompt("*SW3 Password*",self.sw3_password)
		self.sw4_username = self.secret_prompt("*SW4 Username*",self.sw4_username)
		self.sw4_password = self.hidden_secret_prompt("*SW4 Password*",self.sw4_password)
		self.sw5_username = self.secret_prompt("*SW5 Username*",self.sw5_username)
		self.sw5_password = self.hidden_secret_prompt("*SW5 Password*",self.sw5_password)
		self.sw6_username = self.secret_prompt("*SW6 Username*",self.sw6_username)
		self.sw6_password = self.hidden_secret_prompt("*SW6 Password*",self.sw6_password)
		self.sw7_username = self.secret_prompt("*SW7 Username*",self.sw7_username)
		self.sw7_password = self.hidden_secret_prompt("*SW7 Password*",self.sw7_password)
		self.prox1_username = self.secret_prompt("*Prox1 Username*",self.prox1_username)
		self.prox1_password = self.hidden_secret_prompt("*Prox1 Password*",self.prox1_password)
		self.dns_server_1_username = self.secret_prompt("*DNS Server 1 Username*",self.dns_server_1_username)
		self.dns_server_1_password = self.hidden_secret_prompt("*DNS Server 1 Password*",self.dns_server_1_password)
		self.dns_web_api_password = self.hidden_secret_prompt("*DNS Web API Password*",self.dns_web_api_password)
		self.ldap_server_1_username = self.secret_prompt("*LDAP Server 1 Username*",self.ldap_server_1_username)
		self.ldap_server_1_password = self.hidden_secret_prompt("*LDAP Server 1 Password*",self.ldap_server_1_password)
		self.ldap_password = self.hidden_secret_prompt("*LDAP Password*",self.ldap_password)
		self.radius_server_1_username = self.secret_prompt("*Radius Server 1 Username*",self.radius_server_1_username)
		self.radius_server_1_password = self.hidden_secret_prompt("*Radius Server 1 Password*",self.radius_server_1_password)
		self.radius_password = self.hidden_secret_prompt("*Radius Password*",self.radius_password)

	def secret_prompt(self, name, value):
		while True:
			if value == "" or value is None:
				LOGGER.debug(f"{name} secret is empty.")
				value=input(f"Enter a valid {name}: ")
				if value != "" and value is not None:
					return value
			else:
				if(input_yes_no(f"Would you like to reenter the correct {name}? (y/n): ") ):
					value = input(f"Enter a valid {name}: ")
					if value != "" and value is not None:
						return value
	def hidden_secret_prompt(self, name, value):
		while True:
			if value == "" or value is None:
				LOGGER.debug(f"{name} secret is empty.")
				value1 = getpass.getpass(f"Enter a valid {name}: ")
				value2 = getpass.getpass(f"Re-enter the {name} to confirm: ")
				if value1 == value2 and value1 != "" and value1 is not None:
					return value1
				else:
					print("Entries did not match. Try again.")
			else:
				if input_yes_no(f"Would you like to reenter the correct {name}? (y/n): "):
					while True:
						value1 = getpass.getpass(f"Enter a valid {name}: ")
						value2 = getpass.getpass(f"Re-enter the {name} to confirm: ")
						if value1 == value2 and value1 != "" and value1 is not None:
							return value1
						else:
							print("Entries did not match. Try again.")
	def ip_prompt(self, name, value):
		while True:
			try:
				ip_address = ipaddress.ip_address(value)
			except ValueError:
				ip_address = None
			if not ip_address:
				LOGGER.warning(f"{name} is not a valid IPv4 address.")
				value = (input(f"Enter a valid IPv4 address for {name} IPv4 address: "))
			else:
				if(input_yes_no(f"Is {str(value)} the correct IPv4 address for {name}? (y/n): ")):
					return value
				else:
					LOGGER.info(f"Erasing IPv4 address for {name} and trying again.")
					value = None
	def load_data(self):
		config = configparser.ConfigParser()
		config.read(f'{self.app_path.parent.parent}/config.ini')
		missing_data = False

		if 'General' not in config:
			LOGGER.warning("'General' section not found in repo_globals.ini")
			missing_data = True
		try:
			self.telnet_transfer_path = config['General']['telnet_transfer_path']
		except KeyError as e:
			LOGGER.warning(f"Missing telnet_transfer_path: {e}")
			missing_data = True

		if 'Lab_Hypervisor' not in config:
			LOGGER.warning("'Lab_Hypervisor' section not found in repo_globals.ini")
			missing_data = True
		try:
			self.hypervisor_ipv4_address = (ipaddress.ip_address)(config['Lab_Hypervisor']['ipv4_address'])
		except KeyError as e:
			LOGGER.warning(f"Missing key ipv4_address: {e}")
			missing_data = True
		except ValueError as e:
			LOGGER.warning(f"ipv4_address is not a valid IP address: {e}")
			missing_data = True
		try:
			self.hypervisor_ssh_username = config['Lab_Hypervisor']['ssh_user']
		except KeyError as e:
			LOGGER.warning(f"Missing key ssh_user: {e}")
			missing_data = True
		try:
			self.hypervisor_ssh_port = config['Lab_Hypervisor']['ssh_port']
		except KeyError as e:
			LOGGER.warning(f"Missing key ssh_port: {e}")
			missing_data = True
		try:
			self.hypervisor_ssh_password = config['Lab_Hypervisor']['ssh_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key ssh_password: {e}")
			missing_data = True
		try:
			self.lab_username = config['Lab_Hypervisor']['lab_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key lab_username: {e}")
			missing_data = True
		try:
			self.lab_password = config['Lab_Hypervisor']['lab_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key lab_password: {e}")
			missing_data = True

		if 'Network_Nodes' not in config:
			LOGGER.warning("'Network_Nodes' section not found in repo_globals.ini")
			missing_data = True
		try:
			self.r1_username = config['Network_Nodes']['r1_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key r1_username: {e}")
			missing_data = True
		try:
			self.r1_password = config['Network_Nodes']['r1_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key r1_password: {e}")
			missing_data = True
		try:
			self.r1_ca_password = config['Network_Nodes']['r1_ca_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key r1_ca_password: {e}")
			missing_data = True
		try:
			self.ntp_password = config['Network_Nodes']['ntp_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key ntp_password: {e}")
			missing_data = True
		try:
			self.r2_username = config['Network_Nodes']['r2_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key r2_username: {e}")
			missing_data = True
		try:
			self.r2_password = config['Network_Nodes']['r2_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key r2_password: {e}")
			missing_data = True
		try:
			self.r3_username = config['Network_Nodes']['r3_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key r3_username: {e}")
			missing_data = True
		try:
			self.r3_password = config['Network_Nodes']['r3_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key r3_password: {e}")
			missing_data = True
		try:
			self.sw1_username = config['Network_Nodes']['sw1_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw1_username: {e}")
			missing_data = True
		try:
			self.sw1_password = config['Network_Nodes']['sw1_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw1_password: {e}")
			missing_data = True
		try:
			self.sw2_username = config['Network_Nodes']['sw2_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw2_username: {e}")
			missing_data = True
		try:
			self.sw2_password = config['Network_Nodes']['sw2_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw2_password: {e}")
			missing_data = True
		try:
			self.sw3_username = config['Network_Nodes']['sw3_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw3_username: {e}")
			missing_data = True
		try:
			self.sw3_password = config['Network_Nodes']['sw3_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw3_password: {e}")
			missing_data = True
		try:
			self.sw4_username = config['Network_Nodes']['sw4_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw4_username: {e}")
			missing_data = True
		try:
			self.sw4_password = config['Network_Nodes']['sw4_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw4_password: {e}")
			missing_data = True
		try:
			self.sw5_username = config['Network_Nodes']['sw5_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw5_username: {e}")
			missing_data = True
		try:
			self.sw5_password = config['Network_Nodes']['sw5_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw5_password: {e}")
			missing_data = True
		try:
			self.sw6_username = config['Network_Nodes']['sw6_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw6_username: {e}")
			missing_data = True
		try:
			self.sw6_password = config['Network_Nodes']['sw6_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw6_password: {e}")
			missing_data = True
		try:
			self.sw7_username = config['Network_Nodes']['sw7_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw7_username: {e}")
			missing_data = True
		try:
			self.sw7_password = config['Network_Nodes']['sw7_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key sw7_password: {e}")
			missing_data = True

		if 'Servers' not in config:
			LOGGER.warning("'Servers' section not found in repo_globals.ini")
			missing_data = True
		try:
			self.prox1_username = config['Servers']['prox1_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key prox1_username: {e}")
			missing_data = True
		try:
			self.prox1_password = config['Servers']['prox1_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key prox1_password: {e}")
			missing_data = True
		try:
			self.dns_server_1_username = config['Servers']['dns_server_1_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key dns_server_1_username: {e}")
			missing_data = True
		try:
			self.dns_server_1_password = config['Servers']['dns_server_1_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key dns_server_1_password: {e}")
			missing_data = True
		try:
			self.dns_web_api_password = config['Servers']['dns_web_api_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key dns_web_api_password: {e}")
			missing_data = True
		try:
			self.ldap_server_1_username = config['Servers']['ldap_server_1_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key ldap_server_1_username: {e}")
			missing_data = True
		try:
			self.ldap_server_1_password = config['Servers']['ldap_server_1_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key ldap_server_1_password: {e}")
			missing_data = True
		try:
			self.ldap_password = config['Servers']['ldap_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key ldap_password: {e}")
			missing_data = True
		try:
			self.radius_server_1_username = config['Servers']['radius_server_1_username']
		except KeyError as e:
			LOGGER.warning(f"Missing key radius_server_1_username: {e}")
			missing_data = True
		try:
			self.radius_server_1_password = config['Servers']['radius_server_1_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key radius_server_1_password: {e}")
			missing_data = True
		try:
			self.radius_password = config['Servers']['radius_password']
		except KeyError as e:
			LOGGER.warning(f"Missing key radius_password: {e}")
			missing_data = True
		
		if(missing_data):
			LOGGER.warning("Missing data.")
			validate = input("Would you like to validate the data? (y/n): ")
			if(validate == "y"):
				GLOBALS.validate_data()
			else:
				LOGGER.error("Data validation rejected. Exiting.")
				exit()
		self.write()
GLOBALS = Globals()