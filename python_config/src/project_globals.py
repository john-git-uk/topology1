import ipaddress
import logging
import libvirt
import os
from pathlib import Path
import configparser
from dotenv import load_dotenv
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
		self.hypervisor_ssh_host = None
		self.hypervisor_ssh_username = None
		self.hypervisor_ssh_password = None
		self.hypervisor_ssh_port = 0
		self.hypervisor_ssh_key = None
		self.lab_username = None
		self.lab_password = None
		self.telnet_transfer_path = None

	def write(self):
		LOGGER.error("Writing globals is not implemented yet. Exiting.")
		exit()
	def validate_data(self):
		#LOGGER.error("Validating globals is not implemented yet. Exiting.")
		#exit()
		
		# Check hypervisor SSH host is a valid IPv4 address
		valid_hypervisor_ssh_host = False
		while not valid_hypervisor_ssh_host:
			try:
				ip_address = ipaddress.ip_address(self.hypervisor_ssh_host)
			except ValueError:
				ip_address = None
			if not ip_address:
				LOGGER.warning("Hypervisor SSH host is not a valid IPv4 address.")
				self.hypervisor_ssh_host = (input("Please enter a valid IPv4 address for the hypervisor SSH IPv4 address: "))
			else:
				if(input("Is "+str(self.hypervisor_ssh_host)+" the correct hypervisor SSH IPv4 address? (y/n): ") == "y"):
					valid_hypervisor_ssh_host = True
				else:
					LOGGER.info("Erasing hypervisor SSH IPv4 address and trying again.")
					self.hypervisor_ssh_host = None
		# Check hypervisor SSH port is a valid port number
		valid_hypervisor_ssh_port = False
		while not valid_hypervisor_ssh_port:
			try:
				port = int(self.hypervisor_ssh_port)
			except ValueError:
				port = None
			if port < 1 or port > 65535:
				LOGGER.warning("Hypervisor SSH port is not a valid port number.")
				self.hypervisor_ssh_port=input("Please enter a valid port number for the hypervisor SSH port: ")
			else:
				if(input("Is "+str(self.hypervisor_ssh_port)+" the correct hypervisor SSH port? (y/n): ") == "y"):
					valid_hypervisor_ssh_port = True
				else:
					self.hypervisor_ssh_port=input("Please enter a valid port number for the hypervisor SSH port: ")

		
		# Check hypervisor SSH username is not empty
		valid_hypervisor_ssh_username = False
		while not valid_hypervisor_ssh_username:
			if self.hypervisor_ssh_username == "":
				LOGGER.warning("Hypervisor SSH username is empty.")
				self.hypervisor_ssh_username=input("Please enter a valid username for the hypervisor SSH host: ")
			else:
				if(input("Would you like to reenter the correct hypervisor SSH username? (y/n): ") == "y"):
					self.hypervisor_ssh_username = input("Please enter a valid username for the hypervisor SSH host: ")
				else:
					valid_hypervisor_ssh_username = True
		
		# Check hypervisor SSH password is not empty
		valid_hypervisor_ssh_password = False
		while not valid_hypervisor_ssh_password:
			if self.hypervisor_ssh_password == "":
				LOGGER.warning("Hypervisor SSH password is empty.")
				self.hypervisor_ssh_password=input("Please enter a valid password for the hypervisor SSH host: ")
			else:
				if(input("Would you like to reenter the correct hypervisor SSH password? (y/n): ") == "y"):
					self.hypervisor_ssh_password = input("Please enter a valid password for the hypervisor SSH host: ")
				else:
					valid_hypervisor_ssh_password = True
		
		# Check hypervisor SSH key is not empty
		valid_hypervisor_ssh_key = False
		while not valid_hypervisor_ssh_key:
			if self.hypervisor_ssh_key == "":
				LOGGER.warning(" Hypervisor SSH key is empty.")
				self.hypervisor_ssh_key=input("Please enter a valid key for the hypervisor SSH host: ")
			else:
				if(input("Would you like to reenter the correct hypervisor SSH key? (y/n): ") == "y"):
					self.hypervisor_ssh_key = input("Please enter a valid key for the hypervisor SSH host: ")
				else:
					valid_hypervisor_ssh_key = True
		
		# Check lab username
		valid_lab_username = False
		while not valid_lab_username:
			if self.lab_username == "":
				LOGGER.warning("Lab username is empty.")
				self.lab_username=input("Please enter a valid username for the lab: ")
			else:
				if(input("Would you like to reenter the correct lab username? (y/n): ") == "y"):
					self.lab_username = input("Please enter a valid username for the lab: ")
				else:
					valid_lab_username = True
		# Check lab password
		valid_lab_password = False
		while not valid_lab_password:
			if self.lab_password == "":
				LOGGER.warning("Lab password	is empty.")
				self.lab_password=input("Please enter a valid password for the lab: ")
			else:
				if(input("Would you like to reenter the correct lab password? (y/n): ") == "y"):
					self.lab_password = input("Please enter a valid password for the lab: ")
				else:
					valid_lab_password = True
	def load_data(self):
		missing_data = False
		# Find globals file
		LOGGER.info("Attempting to find repo_globals.ini")
		# Loop through 1, 2, and 3 directories up
		current_dir = Path.cwd()
		for i in range(1, 4):
			# Get the parent directory i levels up
			parent_dir = current_dir.parents[i-1]

			# Check if the file exists in this directory
			repo_globals_file_path = parent_dir / 'repo_globals.ini'
			if repo_globals_file_path.exists():
				LOGGER.info(f"Found: {repo_globals_file_path}")
				break
		else:
			LOGGER.warning("repo_globals.ini not found within 3 directories up.")
			missing_data = True

		# Find secrets file
		LOGGER.info("Attempting to find secrets.env")
		# Loop through 1, 2, and 3 directories up
		current_dir = Path.cwd()
		for i in range(1, 4):
			# Get the parent directory i levels up
			parent_dir = current_dir.parents[i-1]

			# Check if the file exists in this directory
			secrets_file_path = parent_dir / 'secrets.env'
			if secrets_file_path.exists():
				LOGGER.info(f"Found: {secrets_file_path}")
				break
		else:
			LOGGER.warning("secrets.env not found within 3 directories up.")
			missing_data = True

		# Read configuration
		config = configparser.ConfigParser()
		config.read(repo_globals_file_path)

		# Check if the 'ssh' section exists
		if 'ssh' not in config:
			LOGGER.warning("'ssh' section not found in repo_globals.ini")
			missing_data = True

		try:
			self.hypervisor_ssh_host = config['ssh']['ipv4_address']
		except KeyError as e:
			LOGGER.warning(f"Missing key in 'ssh' section: {e}")
			missing_data = True
		try:
			self.hypervisor_ssh_port = config['ssh']['port']
		except KeyError as e:
			LOGGER.warning(f"Missing key in 'ssh' section: {e}")
			missing_data = True
		try:
			self.telnet_transfer_path = config['paths']['telnet_transfer_path']
			LOGGER.debug(f"telnet_transfer_path: {self.telnet_transfer_path}")
		except KeyError as e:
			LOGGER.warning(f"Missing key in 'paths' section: {e}")
			missing_data = True

		load_dotenv(dotenv_path=secrets_file_path)

		# Access the secrets from the .env file
		self.hypervisor_ssh_username = os.getenv('HYPERVISOR_USER')
		self.hypervisor_ssh_password = os.getenv('HYPERVISOR_PASSWORD')
		self.lab_username = os.getenv('LAB_USERNAME')
		self.lab_password = os.getenv('LAB_PASSWORD')

		if(missing_data):
			LOGGER.warning("Missing data.")
			validate = input("Would you like to validate the data? (y/n): ")
			if(validate == "y"):
				GLOBALS.validate_data()
			else:
				LOGGER.error("Data validation rejected. Exiting.")
				exit()
GLOBALS = Globals()