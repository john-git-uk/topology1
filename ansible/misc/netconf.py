from ncclient import manager
from ncclient.xml_ import to_ele

# Define the NETCONF RPC
netconf_rpc = """
<edit-config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <target>
    <running/>
  </target>
  <config>
    <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
      <banner>
        <login>
          <banner>this was configured with ansible via netconf</banner>
        </login>
      </banner>
    </native>
  </config>
</edit-config>
"""

# Convert the string to an XML element
netconf_rpc_element = to_ele(netconf_rpc)

# Establish a NETCONF session
with manager.connect(
    host="2001:db8:0:3::ff1",
    port=830,
    username="auto",
    password="otua",
    hostkey_verify=False
) as m:
    # Send the NETCONF RPC
    response = m.dispatch(netconf_rpc_element)
    print(response)
