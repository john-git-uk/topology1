from topology_data import *
def R2_Structures(topology: Topology):
	LOGGER.debug("Loading R2 Structures")
	machine_data=get_machine_data("vios-adventerprisek9-m.SPA.159-3.M6")
	if(machine_data == None):
		raise ValueError("Machine data not found")
		
	node_R2_i1=Interface(
		name="e0/0",
		description="Connected to SW4",
		ipv4_address="10.133.2.66",
		ipv4_cidr=31,
		#ipv6_ipv4_address=""
	)
	node_R2_i2=Interface(
		name="e0/1",
		description="Connected to ISP",
		ipv4_address="10.111.10.20",
		ipv4_cidr=31,
		#ipv6_ipv4_address=""
	)
	node_R2_i3=Interface(
		name="e0/2",
		description="Connected to SW3",
		ipv4_address="10.133.2.74",
		ipv4_cidr=31,
		#ipv6_address=""
	)
	node_R2_i4=Interface(
		name="e0/3",
		description="Out of band",
		ipv4_address="192.168.250.2",
		ipv4_cidr=24
	)
	node_R2_i5=Interface(
		name="l0",
		description="l0",
		ipv4_address="10.133.2.2",
		ipv4_cidr=32,
		#ipv6_address=""
	)
	node_R2=Node(
		hostname="R2",
		local_user="auto",
		local_password="otua",
		machine_data=machine_data,
		oob_interface=node_R2_i4
	)
	node_R2.add_interface(node_R2_i1)
	node_R2.add_interface(node_R2_i2)
	node_R2.add_interface(node_R2_i3)
	node_R2.add_interface(node_R2_i4)
	node_R2.add_interface(node_R2_i5)
	topology.add_node(node_R2)
def R2_relations(topology: Topology):
	LOGGER.debug("Loading R2 Relations")
	topology.get_node("R2").get_interface("e0/0").connect_to(topology.get_node("SW4").get_interface("e1/3"))
	topology.get_node("R2").get_interface("e0/1").connect_to(topology.get_node("ISP").get_interface("e0/1"))
	topology.get_node("R2").get_interface("e0/2").connect_to(topology.get_node("SW3").get_interface("e1/2"))
	topology.get_node("R2").get_interface("e0/3").connect_to(topology.exit_interface_oob)
