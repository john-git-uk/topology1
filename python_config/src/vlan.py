from __future__ import annotations
from pydantic import BaseModel
from typing import Optional, List, Dict
import ipaddress
from machine_data import MachineData, get_machine_data
import logging
import os
from netmiko import ConnectHandler, BaseConnection
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
	main_ipv4_netid: ipaddress.IPv4Address
	main_ipv4_cidr: int
	main_fhrp0_ipv4_address: Optional[ipaddress.IPv4Address] = None
	main_fhrp0_priority: Optional[Interface] = None # The fhrp member node with the highest priority
	main_fhrp1_ipv6_address: Optional[ipaddress.IPv6Address] = None
	main_fhrp1_priority: Optional[Interface] = None # The fhrp member node with the highest priority
	main_dhcp_interface: Optional[Interface] = None
	main_dhcp_exclusion_start: Optional[List[ipaddress.IPv4Address]] = None
	main_dhcp_exclusion_end: Optional[List[ipaddress.IPv4Address]] = None

	# Outreach Site
	outreach_ipv4_netid: Optional[ipaddress.IPv4Address] = None
	outreach_ipv4_cidr: Optional[int] = None
	outreach_dhcp_interface: Optional["Interface"] = None
	outreach_dhcp_exclusion_start: Optional[List[ipaddress.IPv4Address]] = None
	outreach_dhcp_exclusion_end: Optional[List[ipaddress.IPv4Address]] = None

