from topology_data import *
def R1_Structures(topology: Topology):
	LOGGER.debug("Loading R1 Structures")
	machine_data=get_machine_data("catalyst8000v-17.04.01")
	if(machine_data == None):
		raise ValueError("Machine data not found")
	
	node_R1_i1=Interface(
		name="g1",
		description="Connected to SW3",
		ipv4_address="10.133.2.64",
		ipv4_cidr=31,
		#ipv6_address="",
		#ipv6_cidr=127
	)
	node_R1_i2=Interface(
		name="g2",
		description="Connected to ISP",
		ipv4_address="10.111.10.10",
		ipv4_cidr=31,
		ipv6_address=ipaddress.IPv6Address("2001:db8:0:00ff::ffff"),
		ipv6_cidr=127
	)
	node_R1_i3=Interface(
		name="g3",
		description="Connected to SW4",
		ipv4_address="10.133.2.72",
		ipv4_cidr=31,
		#ipv6_address="",
		#ipv6_cidr=127
	)
	node_R1_i4=Interface(
		name="g4",
		description="Out of band",
		ipv4_address="192.168.250.1",
		ipv4_cidr=24,
		#ipv6_cidr=127
	)
	node_R1_i5=Interface(
		name="l0",
		description="l0",
		ipv4_address="10.133.2.1",
		ipv4_cidr=32,
		#ipv6_address="",
		#ipv6_cidr=127
	)
	node_R1=Node(
		hostname="R1",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_R1_i4
	)
	node_R1.add_interface(node_R1_i1)
	node_R1.add_interface(node_R1_i2)
	node_R1.add_interface(node_R1_i3)
	node_R1.add_interface(node_R1_i4)
	node_R1.add_interface(node_R1_i5)
	topology.add_node(node_R1)
def R1_relations(topology: Topology):
	LOGGER.debug("Loading R1 Relations")
	topology.get_node("R1").get_interface("g1").connect_to(topology.get_node("SW3").get_interface("e4/0"))
	topology.get_node("R1").get_interface("g2").connect_to(topology.get_node("ISP").get_interface("e0/0"))
	topology.get_node("R1").get_interface("g3").connect_to(topology.get_node("SW4").get_interface("e2/1"))
	topology.get_node("R1").get_interface("g4").connect_to(topology.exit_interface_oob)