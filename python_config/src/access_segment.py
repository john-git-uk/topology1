from __future__ import annotations
import logging
from pydantic import BaseModel
from typing import Optional, List
LOGGER = logging.getLogger('my_logger')
class AccessSegment(BaseModel):
	class Config:
		debug = True # Enable debug mode
		validate_assignment = True
		arbitrary_types_allowed = True
		from_attributes = True
		fields = {
		}
	name: str = ""
	vlans: List[VLAN]=[]
	nodes: List[Node]=[]
	fhrp: List[Node]=[]
	def get_vlan(self, name: str):
		for vlan in self.vlans:
			if vlan.name == name:
				return vlan
	def get_vlan_nom(self, number: int):
		for vlan in self.vlans:
			if vlan.number == number:
				return vlan