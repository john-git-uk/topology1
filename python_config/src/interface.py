from __future__ import annotations
from pydantic import BaseModel
from typing import Optional, List, Dict
import ipaddress
from machine_data import MachineData, get_machine_data
import logging
import os
from netmiko import ConnectHandler, BaseConnection
LOGGER = logging.getLogger('my_logger')

class Interface(BaseModel):
	def __repr__(self):
		return f"Interface(name={self.name})"
	class Config:
		debug = True # Enable debug mode
		validate_assignment = True
		arbitrary_types_allowed = True
		from_attributes = True
		fields = {
			'interfaces': {'exclude': True},
			'neighbour': {'exclude': True},
			'node_a_part_of': {'exclude': True},
			'vlans': {'exclude': True},
		}
	node_a_part_of: Optional["Node"] = None
	neighbour: Optional["Interface"] = None
	name: str
	interface_type: Literal["ethernet", "fastethernet", "gigabitethernet", "bridge", "vlan", "port-channel", "tunnel", "loopback", "mactap"]
	description: Optional[str]=None
	ospf_participant: bool=False
	ospf_passive: bool=False,
	interfaces: List["Interface"]=[] # For port-channel
	# TODO: Was channel group zero actually undefined or was it used by cisco?
	channel_group: Optional[int]=None
	ipv4_address: Optional[ipaddress.IPv4Address]=None
	ipv4_cidr: Optional[int]=None
	ipv6_address: Optional[ipaddress.IPv6Address]=None
	ipv6_cidr: Optional[int]=None
	#Optional[ipv4_address: List[ipaddress.IPv4Address]]=None
	#Optional[ipv4_cidr: List[int]]=None
	#Optional[ipv6_address: List[ipaddress.IPv6Address]]=None
	#Optional[ipv6_cidr: List[int]]=None
	tunnel_destination: Optional[Interface]=None
	trunk: Optional[bool]=None
	vlans: List["VLAN"]=[]
	def add_vlan(self, vlan: "VLAN"):
		self.vlans.append(vlan)
	def is_vlan_assigned(self, vlan: "VLAN"):
		return vlan in self.vlans
	def connect_to(self, neighbour: "Interface"):
		self.neighbour = neighbour
