from pydantic import BaseModel
from typing import Optional
import logging
LOGGER = logging.getLogger('my_logger')
class MachineData(BaseModel):
	name: str
	device_type: Optional[str] = None
	category: str
	ssh_support: bool
	netconf_support: bool
	restconf_support: bool
	encryption: Optional[str] = None
	switch: Optional[bool] = None
	multilayer: Optional[bool] = None
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
		encryption=None
	)
	m2=MachineData(
		name="vios-adventerprisek9-m.SPA.159-3.M6",
		device_type="cisco_ios",
		category="router",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		encryption=None
	)
	m3=MachineData(
		name="iosv-159-3-m6",
		device_type="cisco_ios",
		category="unknown",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		encryption=None,
		switch=False,
		multilayer=False
	)
	m4=MachineData(
		name="viosl2-adventerprisek9-m.ssa.high_iron_20200929",
		device_type="cisco_ios",
		category="multilayer",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		encryption=None
	)
	m5=MachineData(
		name="iosvl2-2020",
		device_type="cisco_ios",
		category="unknown",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		encryption=None,
		switch=False,
		multilayer=False
	)
	m6=MachineData(
		name="vwlc-8.10.171",
		device_type="cisco_ios",
		category="wlc",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		encryption=None,
		switch=False,
		multilayer=False
	)
	m_debian=MachineData(
		name="debian",
		device_type="debian",
		category="host",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		encryption=None,
		multilayer=True
	)
	m_alpine=MachineData(
		name="alpine",
		device_type="alpine",
		category="host",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		encryption=None,
		multilayer=True
	)
	m_ubuntu=MachineData(
		name="ubuntu",
		device_type="debian",
		category="host",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		encryption=None,
		multilayer=True
	)
	m_proxmox=MachineData(
		name="proxmox",
		device_type="proxmox",
		category="host",
		ssh_support=True,
		netconf_support=False,
		restconf_support=False,
		encryption=None,
		multilayer=True
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
	return machine_data
MACHINE_DATA = structure_machine_data()
# Example usage:
def get_machine_data(machine_name):
	#LOGGER.debug(MACHINE_DATA)
	for data in MACHINE_DATA:
		if data.name == machine_name:
			return data
	return None