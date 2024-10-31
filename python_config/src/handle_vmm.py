from __future__ import annotations
from node import Node
import logging
import psutil
import re
import pexpect
import libvirt
import os
from pathlib import Path
import time
from project_globals import GLOBALS
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
def kill_virsh_console_processes():
	"""
	Searches for and terminates any active 'virsh' processes that include 'console' in their command line.
	"""
	LOGGER.info("Attempting to kill any active 'virsh' processes that include 'console' in their command line.")
	# List to keep track of processes to terminate
	processes_to_kill = []

	# Iterate over all running processes
	for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
		try:
			name = proc.info['name']
			cmdline = proc.info['cmdline']

			# Check if process is 'virsh' with 'console' in arguments
			if name.lower() == 'virsh' and cmdline and 'console' in cmdline:
				processes_to_kill.append(proc)
		except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
			# Skip processes that no longer exist or cannot be accessed
			continue

	if not processes_to_kill:
		LOGGER.info("No active 'virsh console' processes found.")
		return

	LOGGER.info(f"Found {len(processes_to_kill)} active 'virsh console' process(es):")
	for proc in processes_to_kill:
		LOGGER.debug(f"  PID: {proc.pid}, CMD: {' '.join(proc.info['cmdline'])}")

	for proc in processes_to_kill:
		try:
			LOGGER.info(f"PID {proc.pid} did not terminate gracefully. Killing it...")
			proc.kill()  # Sends SIGKILL
		except psutil.NoSuchProcess:
			LOGGER.info(f"  PID {proc.pid} does not exist anymore...")
		except psutil.AccessDenied:
			LOGGER.warning(f"  Access denied when trying to kill PID {proc.pid}. Try running the script as root.")
		except Exception as e:
			LOGGER.error(f"  Failed to kill PID {proc.pid}: {e}")

	LOGGER.info("Finished killing 'virsh console' processes.")
def strip_ansi_escape(text):
	ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
	return ansi_escape.sub('', text)
def get_shell_prompt(child):
	"""
	Detects the current shell prompt by sending a unique command and capturing the prompt.
	"""
	unique_marker = "PEXPECT_PROMPT_DETECTION"
	child.sendline(f'echo "{unique_marker}"')
	
	try:
		# Wait for the unique marker to appear in the output
		child.expect(unique_marker, timeout=5)
		
		# After the unique marker, the prompt should appear
		child.expect(['\r\n', '\n'], timeout=1)
		
		# Now, capture the prompt by expecting a common prompt ending
		child.expect([r'\$ ', r'# '], timeout=5)
		prompt = child.after.strip()
		prompt = strip_ansi_escape(prompt)  # Remove any ANSI codes
		return prompt
	except pexpect.exceptions.TIMEOUT:
		LOGGER.warning("Failed to detect shell prompt.")
		return None
	except pexpect.exceptions.EOF:
		LOGGER.warning("Shell exited unexpectedly while detecting prompt.")
		return None
def is_vmm_node_running(machine: Node):
	"""
	Checks if a machine is running.
	"""
	LOGGER.debug(f"Checking if {machine.hostname} is running")
	kill_virsh_console_processes()
	# Check if the machine is running
	try:
		conn = libvirt.open('qemu:///system')
		print("Connection successful!")

		try:
			domain = conn.lookupByName(machine.hostname)
		except libvirt.libvirtError:
			print(f"No such qemu machine: {machine.hostname}")
			return
		info = domain.info()
		LOGGER.debug(f'This is the info from qemu about {machine.hostname}: {info}')
		conn.close()
		
		state_str = VIR_DOMAIN_STATE_LOOKUP.get(info[0], 'Unknown State')
		LOGGER.debug(f'This should say Running: {state_str}')
		if(state_str == 'Running'):
			return True
		else:
			return False
	except libvirt.libvirtError as e:
		LOGGER.warning(f"Failed to connect to the hypervisor: {e}")
def test_interact_vmm(topology):
	machine = "prox1"
	# find_machine_by_name(machine)
	for node in topology.nodes:
		if node.hostname == machine:
			if(is_vmm_node_running(node)):
				send_bash("ip addr show", node)
			else:
				LOGGER.warning("QEMU node is not running.")
def send_bash(command: str, machine: Node):
	escaped_machine = re.escape(machine.hostname)
	escaped_username = re.escape(machine.local_user)
	escaped_password = re.escape(machine.local_password)
	#escaped_command = re.escape(command) # This is not needed
	escaped_command = (command)

	log_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "logs"
	log_path.mkdir(exist_ok=True, parents=True)
	with open(os.path.join(log_path,"pexpect_raw.log"), 'w') as pexpect_log_file:
		child = pexpect.spawn('/bin/bash', encoding='utf-8', timeout=10)# Enable comprehensive logging to the file
		child.logfile = pexpect_log_file  # Log all interactions to 'pexpect_log.txt'

		child.expect([r'\$ ', r'# '], timeout=5)
		
		# Detect the current prompt
		current_prompt = get_shell_prompt(child)
		
		if not current_prompt:
			print("Could not detect the shell prompt. Exiting.")
			return

		print(f"Detected Prompt: '{current_prompt}'")
		
		#escaped_command = "echo 'Hello from Python!' && ip addr show"
		LOGGER.info(f'Attempting to log into {machine.hostname} via virtual console')
		child.sendline(f'virsh --connect qemu:///system console {machine.hostname}')
		time.sleep(1)
		child.expect(r'.*Escape character is \^\] \(Ctrl \+ \]\)', timeout=10)
		child.sendline()
		time.sleep(1)
		child.expect([fr'.*{escaped_machine} login:'])
		child.sendline(f'{escaped_username}')
		time.sleep(1)
		child.expect(r'.*Password:', timeout=10)
		child.sendline(f'{escaped_password}')
		time.sleep(1)
		child.expect([fr'.*{escaped_username}@{escaped_machine}:',r'.*Login incorrect'], timeout=10)
		if(child.after.strip() == r'.*Login incorrect'):
			LOGGER.error(f'Login incorrect for logging into {machine.hostname} virtual console')
			return
		child.sendline(escaped_command)
		time.sleep(2)
		child.expect(fr'.*{escaped_username}@{escaped_machine}:', timeout=10)
				
		# The output of the command is in child.before
		# It includes everything from after sendline up to the prompt
		#LOGGER.debug(f'this is the output were working with:{child.after}')
		output = child.after.strip()
		
		# Clean any ANSI escape codes from output
		output = strip_ansi_escape(output)

		# Remove the command itself from the output if echoed back
		# This depends on shell settings (e.g., echo is on)
		if output.startswith(f'~# {escaped_command}'):
			output = output[len(f'~# {escaped_command}'):].strip()
		if output.endswith(f'{escaped_username}@{escaped_machine}:'):
			output = output[:-len(f'{escaped_username}@{escaped_machine}:')].strip()
		# remove trailing newlines
		output = output.rstrip()
		# remove leading newlines
		output = output.lstrip()
		time.sleep(1)
		child.sendline("logout")
		time.sleep(1)
		# Send the escape sequence to exit the console
		child.send('\x1d')  # Sends Ctrl + ]
		LOGGER.debug("Sent escape sequence to exit the console.")
		
		time.sleep(2)
		
		# Close the child process
		child.close()
		LOGGER.debug("pexpect process closed gracefully.")

		LOGGER.debug(f"Command Output:\n{output}")
		
		# Save the output to a file
		out_path = Path(GLOBALS.app_path).parent.resolve() / "output" / "logs"
		out_path.mkdir(exist_ok=True, parents=True)
		with open(os.path.join(os.path.abspath(out_path),'vmm_command_result.log'), 'w') as output_file:
			output_file.write(output)
		
		return output