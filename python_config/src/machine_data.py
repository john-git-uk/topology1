from pydantic import BaseModel
from typing import Optional
import logging
LOGGER = logging.getLogger('my_logger')
class MachineData(BaseModel):
	name: str
	filename: Optional[str] = None
	device_type: Optional[str] = None
	category: str
	ssh_support: bool
	netconf_support: bool
	restconf_support: bool

	gigabit_naming: bool
	# This could be a list of different sized groups, but it is instead for every port group on node.
	dot3_port_group_size: int
	ssh_options: Optional[list] = []
def structure_machine_data():
	# Creating instances for each machine
	machine_data=[]

	m1=MachineData(
		name="catalyst8000v-17.04.01",
		device_type="cisco_xe",
		category="router",
		ssh_support=True,
		netconf_support=True,
		restconf_support=True,
		gigabit_naming=True,
		dot3_port_group_size=1,
	)
	m2=MachineData(
		name="vios-adventerprisek9-m.SPA.159-3.M6",
		device_type="cisco_ios",
		category="router",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		ssh_options=['KexAlgorithms=+diffie-hellman-group14-sha1', 'MACs=hmac-sha1', 'HostKeyAlgorithms=+ssh-rsa', 'PubkeyAcceptedKeyTypes=+ssh-rsa'],
		gigabit_naming=False,
		dot3_port_group_size=4,
	)
	m3=MachineData(
		name="iosv-159-3-m6",
		device_type="cisco_ios",
		category="unknown",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		ssh_options=['KexAlgorithms=+diffie-hellman-group14-sha1', 'MACs=hmac-sha1', 'HostKeyAlgorithms=+ssh-rsa', 'PubkeyAcceptedKeyTypes=+ssh-rsa'],
		gigabit_naming=False,
		dot3_port_group_size=4,
	)
	m4=MachineData(
		name="viosl2-adventerprisek9-m.ssa.high_iron_20200929",
		device_type="cisco_ios",
		category="multilayer",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		ssh_options=['KexAlgorithms=+diffie-hellman-group14-sha1', 'MACs=hmac-sha1', 'HostKeyAlgorithms=+ssh-rsa', 'PubkeyAcceptedKeyTypes=+ssh-rsa'],
		gigabit_naming=False,
		dot3_port_group_size=4,
	)
	m5=MachineData(
		name="iosvl2-2020",
		device_type="cisco_ios",
		category="unknown",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		ssh_options=['KexAlgorithms=+diffie-hellman-group14-sha1', 'MACs=hmac-sha1', 'HostKeyAlgorithms=+ssh-rsa', 'PubkeyAcceptedKeyTypes=+ssh-rsa'],
		gigabit_naming=False,
		dot3_port_group_size=4,
	)
	m6=MachineData(
		name="vwlc-8.10.171",
		device_type="cisco_ios",
		category="wlc",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		gigabit_naming=False,
		dot3_port_group_size=1,
	)
	m_debian=MachineData(
		name="debian",
		device_type="debian",
		category="host",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		gigabit_naming=False,
		dot3_port_group_size=1,
	)
	m_alpine=MachineData(
		name="alpine",
		device_type="alpine",
		category="host",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		gigabit_naming=False,
		dot3_port_group_size=1,
	)
	m_ubuntu=MachineData(
		name="ubuntu",
		device_type="debian",
		category="host",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		gigabit_naming=False,
		dot3_port_group_size=1,
	)
	m_proxmox=MachineData(
		name="proxmox",
		device_type="proxmox",
		category="host",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		gigabit_naming=False,
		dot3_port_group_size=1,
	)
	m_iou_xe=MachineData(
		name = "Cisco IOU L3 17.12.1",
		filename = 'x86_64_crb_linux_l2-adventerprisek9-ms.bin',
		device_type = "cisco_xe",
		category = "router",
		ssh_support = True,
		netconf_support = False,
		restconf_support = False,
		ssh_options = [],
		gigabit_naming=False,
		dot3_port_group_size=4,
	)
	m_iou_l2_xe=MachineData(
		name = "Cisco IOU L2 17.12.1",
		filename = 'x86_64_crb_linux-adventerprisek9-ms.bin',
		device_type = "cisco_xe",
		category = "multilayer",
		ssh_support = True,
		netconf_support = False,
		restconf_support = False,
		ssh_options = [],
		gigabit_naming=False,
		dot3_port_group_size=4,
	)
	m_c8k_17_09_01a = MachineData(
		name = 'Cisco Catalyst 8000V 17.09.01a 8G',
		filename = 'c8000v-universalk9_8G_serial.17.09.01a.qcow2',
		device_type = "cisco_xe",
		category = "router",
		gigabit_naming=True,
		ssh_support = True,
		netconf_support = True,
		restconf_support = True,
		ssh_options = [],
		dot3_port_group_size=1,
	)

	machine_data.append(m1)
	machine_data.append(m2)
	machine_data.append(m3)
	machine_data.append(m4)
	machine_data.append(m5)
	machine_data.append(m6)
	machine_data.append(m_debian)
	machine_data.append(m_alpine)
	machine_data.append(m_ubuntu)
	machine_data.append(m_proxmox)
	machine_data.append(m_iou_xe)
	machine_data.append(m_iou_l2_xe)
	machine_data.append(m_c8k_17_09_01a)
	return machine_data
MACHINE_DATA = structure_machine_data()
# Example usage:
def get_machine_data(machine_name):
	#LOGGER.debug(MACHINE_DATA)
	for data in MACHINE_DATA:
		if data.name == machine_name:
			return data
	return None