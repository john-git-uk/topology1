from topology_data import *
def SW7_Structures(topology: Topology):
	LOGGER.debug("Loading SW1 Structures")
	machine_data=get_machine_data("viosl2-adventerprisek9-m.ssa.high_iron_20200929")
	if(machine_data == None):
		raise ValueError("Machine data not found")
		
	node_SW7_i1=Interface(
		name="e0/0",
		trunk=True,
		vlans=[
			topology.get_vlan("sales"),
			topology.get_vlan("guest"),
			topology.get_vlan("management"),
			topology.get_vlan("supervisor"),
		]
	)
	node_SW7_i2=Interface(
		name="e0/1",
		trunk=False,
		vlans=[topology.get_vlan("sales")]
	)
	node_SW7_i3=Interface(
		name="e0/2",
		trunk=False,
		vlans=[topology.get_vlan("sales")]
	)
	node_SW7_i4=Interface(
		name="e0/3",
		trunk=False,
		vlans=[topology.get_vlan("sales")]
	)
	node_SW7_i5=Interface(
		name="e1/0",
		trunk=False,
		vlans=[topology.get_vlan("supervisor")]
	)
	node_SW7_i6=Interface(
		name="e1/1",
		trunk=False,
		vlans=[topology.get_vlan("guest")]
	)
	node_SW7_i7=Interface(
		name="e1/2",
		trunk=False,
		vlans=[topology.get_vlan("guest")]
	)
	node_SW7_i8=Interface(
		name="e1/3",
		trunk=False,
		vlans=[topology.get_vlan("guest")]
	)
	node_SW7_i9=Interface(
		name="e2/0",
		trunk=False,
		vlans=[topology.get_vlan("guest")]
	)
	node_SW7_i10=Interface(
		name="e2/1",
		trunk=False,
		vlans=[topology.get_vlan("guest")]
	)
	node_SW7_i11=Interface(
		name="e3/3",
		description="out of band",
		ipv4_address="192.168.250.57",
		ipv4_cidr=24
	)
	node_SW7_i12=Interface(
		name="vlan 30",
		description="",
		ipv4_address="10.133.30.137",
		ipv4_cidr=25
	)
	node_SW7_i13=Interface(
		name="l0",
		description="",
		ipv4_address="10.133.2.17",
		ipv4_cidr=32
	)
	node_SW7 = Node(
		hostname="SW7",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_SW7_i11
	)
	node_SW7.add_interface(node_SW7_i1)
	node_SW7.add_interface(node_SW7_i2)
	node_SW7.add_interface(node_SW7_i3)
	node_SW7.add_interface(node_SW7_i4)
	node_SW7.add_interface(node_SW7_i5)
	node_SW7.add_interface(node_SW7_i6)
	node_SW7.add_interface(node_SW7_i7)
	node_SW7.add_interface(node_SW7_i8)
	node_SW7.add_interface(node_SW7_i9)
	node_SW7.add_interface(node_SW7_i10)
	node_SW7.add_interface(node_SW7_i11)
	node_SW7.add_interface(node_SW7_i12)
	node_SW7.add_interface(node_SW7_i13)
	topology.add_node(node_SW7)
def SW7_relations(topology: Topology):
	LOGGER.debug("Loading SW1 Relations")
	topology.get_node("SW7").get_interface("e0/0").connect_to(topology.get_node("R3").get_interface("e0/1"))
	topology.get_node("SW7").get_interface("e3/3").connect_to(topology.exit_interface_oob)
