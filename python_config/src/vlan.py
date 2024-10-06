from __future__ import annotations
from pydantic import BaseModel
from typing import Optional, List, Dict
import ipaddress
import logging
LOGGER = logging.getLogger('my_logger')

class VLAN(BaseModel):
	def __repr__(self):
		return f"VLAN(name={self.name})"
	class Config:
		validate_assignment = True
		arbitrary_types_allowed = True
		from_attributes = True
		fields = {
			'main_dhcp_exclusion_start': {'exclude': True},
			'main_dhcp_exclusion_end': {'exclude': True},
			'outreach_dhcp_exclusion_start': {'exclude': True},
			'outreach_dhcp_exclusion_end': {'exclude': True},
		}
	number: int
	name: str

	# Main Site
	ipv4_netid: ipaddress.IPv4Address
	ipv4_cidr: int
	fhrp0_ipv4_address: Optional[ipaddress.IPv4Address] = None
	fhrp0_priority: Optional[Interface] = None # The fhrp member node with the highest priority
	#fhrp0_interfaces: Optional[List[Interface]] = []
	fhrp1_ipv6_address: Optional[ipaddress.IPv6Address] = None
	fhrp1_priority: Optional[Interface] = None # The fhrp member node with the highest priority
	dhcp_interface: Optional[Interface] = None
	dhcp_exclusion_start: Optional[List[ipaddress.IPv4Address]] = []
	dhcp_exclusion_end: Optional[List[ipaddress.IPv4Address]] = []

	# Outreach Site
	ipv4_netid: Optional[ipaddress.IPv4Address] = None
	ipv4_cidr: Optional[int] = None
	dhcp_interface: Optional["Interface"] = None
	dhcp_exclusion_start: Optional[List[ipaddress.IPv4Address]] = []
	dhcp_exclusion_end: Optional[List[ipaddress.IPv4Address]] = []

	def auto_dhcp_exclude(self, count: int):
		""" Automatically generate a list of excluded addresses at the end of the subnet."""
		if(count == 0):
			LOGGER.info("DHCP exclusion count was 0 so theres nothing to do.")
		if(self.ipv4_netid is None):
			LOGGER.warning("VLAN "+self.name+" had no ipv4_netid when attempting to auto exclude.")
			return
		if(self.ipv4_cidr is None):
			LOGGER.warning("VLAN "+self.name+" had no ipv4_cidr when attempting to auto exclude.")
			return
		# Calculate the number of usable addresses in the subnet
		usable_addresses = 2 ** (32 - self.ipv4_cidr) - 2
		if(usable_addresses < count):
			LOGGER.warning("VLAN "+self.name+" had less usable addresses than the exclusion count. Setting exclusion count to usable addresses.")
			count = usable_addresses
		
		# Calculate the start of the exclusion range by counting down from the last usable address
		last_usable_address = self.ipv4_netid + usable_addresses - 1
		LOGGER.debug(f"Last usable address: {last_usable_address}")
		LOGGER.debug(f"Exclusion count: {count}")
		LOGGER.debug(f"Exclusion start: {last_usable_address - count + 1}")
		LOGGER.debug(f"Exclusion end: {last_usable_address}")
		self.dhcp_exclusion_start += [last_usable_address - count + 1]
		self.dhcp_exclusion_end += [last_usable_address]