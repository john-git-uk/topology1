import yaml
import os

# Add the path to the library folder for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '../library'))

# Import the cidr_to_netmask function from convert_module.py
from convert_module import cidr_to_netmask

# Relative path to the inventory file
inventory_path = os.path.join(os.path.dirname(__file__), '../inventory.yaml')

# Load the YAML inventory file
try:
    with open(inventory_path, 'r') as inventory_file:
        inventory_data = yaml.safe_load(inventory_file)
        print("Inventory loaded successfully.")
except FileNotFoundError:
    print(f"Error: {inventory_path} not found.")
except yaml.YAMLError as exc:
    print(f"Error parsing YAML file: {exc}")

# Access hosts and groups in the inventory
all_hosts = inventory_data.get('all', {}).get('hosts', {})
groups = inventory_data.get('all', {}).get('children', {})

# Print hosts
#print("\nHosts in 'all':")
#for host, vars in all_hosts.items():
#    print(f"Host: {host}, Vars: {vars}")

# Print groups
#print("\nGroups:")
#for group, data in groups.items():
#    print(f"Group: {group}")
#    for host, vars in data.get('hosts', {}).items():
#        print(f"  Host: {host}, Vars: {vars}")

# Print r3 loopback
try:
    r3_interfaces = inventory_data['all']['children']['nodes']['hosts']['r3']['interfaces']
    loopback = r3_interfaces.get('l0')
    if loopback:
        print("Loopback interface on r3:")
        print(f"  Description: {loopback.get('description', 'N/A')}")
        ipv4_info = loopback.get('ipv4', {})
        print(f"  IPv4 Address: {ipv4_info.get('address', 'N/A')}")
        print(f"  CIDR: {ipv4_info.get('cidr', 'N/A')}")
        ipv6_address = loopback.get('ipv6_address', 'N/A')
        print(f"  IPv6 Address: {ipv6_address}")
    else:
        print("No loopback interface (l0) found on r3.")
except KeyError as e:
    print(f"Error: Missing key in inventory data - {e}")
	ipaddress.IPv4Network(f'0.0.0.0/{cidr}', strict=False)