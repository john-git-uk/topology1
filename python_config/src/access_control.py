from pydantic import BaseModel
from typing import List, Dict
import ipaddress
from vlan import VLAN
class Access_Control(BaseModel):
	vlans: List[VLAN]=[]
	allowlist: List[ipaddress.IPv4Network]=[]
	blocklist: List[ipaddress.IPv4Network]=[]