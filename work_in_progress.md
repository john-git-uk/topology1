## OOB
I create out of band interfaces on my network devices and servers that provide services such as SSH only to authorised technicians. I will use 192.168.250.0/24 to address the nodes. The access switch image I am using supports layer 3 and im unsure about the presence of a layer 3 management port on real switches. I decided to **no switchport** the interfaces while keeping **no ip routing**.
#### IPv4 Assignments
~~~
192.168.250.1 - R1
192.168.250.2 - R2
192.168.250.3 - R3
192.168.250.51 - SW1
192.168.250.52 - SW2
192.168.250.53 - SW3
192.168.250.54 - SW4
192.168.250.55 - SW5
192.168.250.56 - SW6
192.168.250.57 - SW7
192.168.250.101 - radius_server
192.168.250.102 - ldap_server
192.168.250.253 - ISP Simulation Node
192.168.250.254 - my pc
~~~
#### All
~~~
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### R1 Config
~~~
int g4
 ip add 192.168.250.1 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### R2 Config
~~~
int e0/3
 ip add 192.168.250.2 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### R3 Config
~~~
int e0/3
 ip add 192.168.250.3 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### SW1 Config
~~~
int e3/3
 no switchport
 ip add 192.168.250.51 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### SW2 Config
~~~
int e3/3
 no switchport
 ip add 192.168.250.52 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### SW3 Config
~~~
int e5/3
 no switchport
 ip add 192.168.250.53 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### SW4 Config
~~~
int e5/3
 no switchport
 ip add 192.168.250.54 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### SW5 Config
~~~
int e3/3
 no switchport
 ip add 192.168.250.55 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### SW6 Config
~~~
int e5/3
 no switchport
 ip add 192.168.250.56 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
#### SW7 Config
~~~
int e3/3
 no switchport
 ip add 192.168.250.57 255.255.255.0
 no shut
exit
ip access sta ssh
 10 permit 192.168.250.0 0.0.0.255
 10000 deny any
exit
line vty 0 4
 access-class ssh in
 access-class ssh out
exit
~~~
####

#### aaa_server Config
I set a password of "toor" on the local root account. This is not secure for outside of a lab.
~~~
passd root
~~~

###### /etc/ssh/sshd_config
I ensure these values are set
~~~
PasswordAuthentication yes
PermitRootLogin yes
UsePAM yes
~~~
###### /root/networkconfig.sh
~~~
#!/bin/bash
ip addr add 10.133.70.251/24 dev eth1
ip link set eth1 up
ip route add default via 10.133.70.254
ip addr add 192.168.250.101/24 dev eth2
ip link set eth2 up
~~~
###### root/starter.sh
This file remains the same as in the image.
###### Testing
~~~
ssh root@192.168.250.101
~~~
## IPv6 ACL(incomplete)
I have yet to configure the IPv6 ACL so it has practically no security.
## Cisco Certificate Authority
I use R1 as a certificate authority for the domain. A certificate authority signs certificates so other nodes on the network know the nodes they communicate with are genuine.

#### R1 Config
~~~
ip http serv
aaa new-model

crypto pki serv CA
  issuer-name CN=CA,O=tapeitup.private
  grant auto
  no shut
~~~

pass:sevenwsad

#### R2 Config
~~~
crypto key generate rsa modulus 2048 label R2.tapeitup.private
crypto pki trustpoint trustedCA
  enrollment url https://10.133.2.1
  rsakeypair R2.tapeitup.private
  subject-name CN=R2,O=tapeitup.private
  revocation-check none
exit
~~~
## Radius (PAM)
Cisco ports need to be set to standard. The default will remain local users. 
This freeradius configuration stores plain text passwords, which is not secure. I could make a more robust aaa server in the future.
NAS-Identifier(Attribute 32) is used to identify the device to the radius server. This means I can lock groups like sales users out of the network devices but not pcs. Apparently a unique secret is not used for identification.
Unfortunately I haven't found a way to change the NAS-Identifier using libpam-radius-auth on Ubuntu via configuration files. I am going to filter using IP address for this machine.
### Cisco IOS Client
~~~
aaa new-model
ip radius source-interface Loopback0

radius server aaa-server-1
 address ipv4 10.133.60.251 auth-port 1812 acct-port 1813
 key R1radiuskey
 exit
aaa group server radius aaa_group
 server name aaa-server-1
 exit

aaa authentication login vty_method group aaa_group
aaa authorization exec default group aaa_group

radius-server attribute 32 include-in-access-req format "Net-Cisco-B@4]-%h"

line vty 0 4
login auth vty_method
~~~
### FreeRadius
#### users
~~~
John Cleartext-Password := "nhoj"
		Reply-Message = "Radius %{User-Name}",
		Service-Type = NAS-Prompt-User,
    Cisco-AVPair = "shell:priv-lvl=15"
    Group = "network_admin"
Dave Cleartext-Password := "evad"
		Reply-Message = "Radius %{User-Name}",
		Service-Type = NAS-Prompt-User
    Group = "sales"
radlab Cleartext-Password := "bal"
		Reply-Message = "Radius %{User-Name}",
		Service-Type = NAS-Prompt-User,
    Cisco-AVPair = "shell:priv-lvl=15"
    Group = "network_admin"
radauto Cleartext-Password := "otua"
		Reply-Message = "Radius %{User-Name}",
    Service-Type = NAS-Prompt-User,
    Cisco-AVPair = "shell:priv-lvl=15"
    Group = "network_admin"
# 
# Cisco Devices
#
DEFAULT Group == "network_admin", NAS-Identifier =~ "Net-Cisco-B@4]"
    Service-Type = Administrative-User,
    Reply-Message = "Admin Access Granted"

DEFAULT Group != "network_admin", NAS-Identifier =~ "Net-Cisco-B@4]"
    Reply-Message := "Access Denied: You do not have the appropriate permissions",
    Auth-Type := Reject
#
# aaa_server
#
DEFAULT Group == "network_admin", NAS-IP-Address == "192.168.250.101",
    Service-Type = Administrative-User,
    Reply-Message = "Admin Access Granted"
    
DEFAULT Group != "network_admin", NAS-IP-Address == "192.168.250.101",
    Reply-Message := "Access Denied: You do not have the appropriate permissions",
    Auth-Type := Reject

DEFAULT Group == "network_admin", NAS-IP-Address == "127.0.0.1",
    Service-Type = Administrative-User,
    Reply-Message = "Admin Access Granted"
    
DEFAULT Group != "network_admin", NAS-IP-Address == "127.0.0.1",
    Reply-Message := "Access Denied: You do not have the appropriate permissions",
    Auth-Type := Reject

DEFAULT Group == "network_admin", NAS-IP-Address == "10.133.70.251",
    Service-Type = Administrative-User,
    Reply-Message = "Admin Access Granted"
    
DEFAULT Group != "network_admin", NAS-IP-Address == "10.133.70.251",
    Reply-Message := "Access Denied: You do not have the appropriate permissions",
    Auth-Type := Reject
~~~
#### clients.conf
~~~
client R1.tapeitup.private {
	ipaddr = 10.133.2.1
  	secret = radiuskey
	shortname = R1
}
client SW3.tapeitup.private {
	ipaddr = 10.133.2.53
  	secret = radiuskey
	shortname = SW3
}
~~~
### Ubuntu Bionic Client
#### /etc/pam.d/sshd
~~~
auth       sufficient   pam_radius_auth.so
~~~
#### /etc/ssh/sshd_config
~~~
UsePAM yes
~~~
~~~
sudo systemctl restart sshd
~~~
## LDAP RADIUS Query
~~~
apt-get install freeradius-ldap
~~~
#### /etc/freeradius/3.0/mods-available/ldap
~~~
ldap {
    server = "ldap://ldap.example.com"
    identity = "cn=admin,dc=example,dc=com"
    password = "your_admin_password"
    basedn = "dc=example,dc=com"
    filter = "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"
    ldap_connections_number = 5
    timeout = 4
    timelimit = 3
    net_timeout = 1
    # Set whether to use the userPassword field for authentication
    password_attribute = "userPassword"
    start_tls = no
    tls_require_cert = "allow"
    compare_check_items = yes
    access_attr_used_for_allow = yes
}
~~~
~~~
sudo ln -s /etc/freeradius/3.0/mods-available/ldap /etc/freeradius/3.0/mods-enabled/ldap
~~~
#### /etc/freeradius/3.0/sites-enabled/default
~~~
authorize {
    ...
    ldap
    ...
}
authenticate {
    ...
    Auth-Type LDAP {
        ldap
    }
    ...
}
~~~


**service freeradius restart**
## proxmox
user:root
pass:toorp
## EAP-TLS
## Restconf/Netconf (incomplete)
#### Bug
Unfortunately due to a bug in this IOS version the clock has to be changed to generate self signed certificates.
https://www.cisco.com/c/en/us/support/docs/field-notices/704/fn70489.html

Im only running one device capable of restconf, R1.

~~~
do clock set 11:11:11 11 jan 2000
~~~
~~~
crypto pki trustpoint https
    enrollment selfsigned
    subject-name CN=lab_device
    revocation-check none
    rsakeypair https
    crypto pki enroll https

crypto key generate rsa modulus 2048 label https

ip http secure-server
ip http secure-trustpoint https
~~~
~~~
virtual-service csr_mgmt
no activate
ip shared host-interface l0
activate
exit
~~~

## Future Topics
~~~
## IPv6 VPN
## FTP Example
## TACACS
## SNMP
## Syslog
## VOIP
## QOS
## RADIUS
## DNS
## Internet Web Service(NAT Amendments etc)
## REST API management with Python
~~~