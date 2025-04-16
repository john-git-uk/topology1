## OOB
I create out of band interfaces on my network devices and servers that provide services such as SSH only to authorised technicians. I will use 192.168.250.0/24 to address the nodes. The access switch image I am using supports layer 3 and im unsure about the presence of a layer 3 management port on real switches. I decided to **no switchport** the interfaces while keeping **no ip routing**.
#### IPv4 Assignments
~~~
192.168.250.1 - r1
192.168.250.2 - r2
192.168.250.3 - r3
192.168.250.51 - sw1
192.168.250.52 - sw2
192.168.250.53 - sw3
192.168.250.54 - sw4
192.168.250.55 - sw5
192.168.250.56 - sw6
192.168.250.57 - sw7
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
#### r1 Config
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
#### r2 Config
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
#### r3 Config
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
#### sw1 Config
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
#### sw2 Config
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
#### sw3 Config
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
#### sw4 Config
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
#### sw5 Config
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
#### sw6 Config
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
#### sw7 Config
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
I use r1 as a certificate authority for the domain. A certificate authority signs certificates so other nodes on the network know the nodes they communicate with are genuine.

#### r1 Config
~~~
ip http server
aaa new-model

access-list 93 permit 10.133.0.0 0.0.255.255
ip http access-class 93

crypto pki serv CA
  issuer-name CN=CA,O=tapeitup.private
  grant auto
  no shut
~~~

pass:sevenwsad

#### r2 Config
~~~
crypto key generate rsa modulus 2048 label r2.tapeitup.private
crypto pki trustpoint trustedCA
  enrollment url http://10.133.2.1
  rsakeypair r2.tapeitup.private
  subject-name CN=r2,O=tapeitup.private
  revocation-check none
exit
crypto pki authenticate trustedCA
crypto pki enroll trustedCA
~~~

#### Debian Config
Print the certificate on r1 using **show crypto pki certificate pem CA**

~~~
rm -f /usr/local/share/ca-certificates/CA.crt
echo "-----BEGIN CERTIFICATE-----
MIIDLjCCAhagAwIBAgIBATANBgkqhkiG9w0BAQsFADAoMRkwFwYDVQQKExB0YXBl
aXr1cC5wcml2YXRlMQswCQYDVQQDEwJDQTAeFw0yNDExMDQwMjA2NTJaFw0yNzEx
MDQwMjA2NTJaMCgxGTAXBgNVBAoTEHRhcGVpdHVwLnByaXZhdGUxCzAJBgNVBAMT
AkNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmqg54goqOr6g1cIV
cY4KNHx+G7PXkndHymiYFwQ/ZPObGY/Ytat26gF8M5q1jZhEApB+FL58hfAg0/I7
7bEimEe99Zno5S+fbrgJ/b5RU0OCgCsHVt7fAw+0bm5JRH6MCqK4rN0f8qhTdJbo
snN7x6j3sPdj3r7WnHSe9FfapVecgon6X+wjQdKEjfHNVJ05TAxecVptkT8JjOuk
2P98CX1CiqJC7bjmEXm2X0ebq/ozbEccRt2tKkh/tB+lMNxuwr8zR8Z6oND6/CDK
hRi++9sa1duxJO0UVUbUD1Gxz98TTithnFpFjq1+VNDiyBr1OLu3Kn+hEGCJR5Ua
5/eFcQIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAf
BgNVHSMEGDAWgBQF9qKSWdCam2bMl636cdr2cNKErTAdBgNVHQ4EFgQUBfaiklnQ
mptmzJet+nHUdnDShK0wDQYJKoZIhvcNAQELBQADggEBAHVMMljCZDpxd5i8DUdy
NhHGov7AuvKBoelPkZGyz7Rrs7P4R76WVt4bmg2DWZ/EsTV7HC95XmXUJG1VjjkO
o/iN0EZPoD6qynsLzSasSyzwBTNoSO50wIQlabwCq3Ik1texPccRFwgCHqWGJBGx
Ja8PK8Xo5/b68aYYSIKDNeqbttj6R9ZdDTikQBiaZjcHIwEssDYl33ivI+qOgxqj
8/gq+J4toku3tfcOupRLX4C9nWLzoNs0mwO2Y9AG4+SSvpwtt49u2bDvwNlNbBUb
1vqlc4zeUIgzxAF/xqm5MIsC8QzwynC75NCrhYB1wKaFHKX5iwQp1NZnc763T+SJ
TB0=
-----END CERTIFICATE-----" > /usr/local/share/ca-certificates/CA.crt
update-ca-certificates --fresh
~~~

## Radius (PAM)
Cisco ports need to be set to RADIUS standard. The default will remain local users. 
This freeradius configuration stores plain text passwords which wouldnt be done outside a lab.
NAS-Identifier(Attribute 32) is used to identify the device to the RADIUS server. This means I can remove access for groups such as sales users out of the network devices but maintain their access to workstations. I have unique keys for each device to prevent impersonation.
  
To properly secure the RADIUS systems it would be better to use RadSec. Otherwise the user can impersonate other devices NAS-Identifier.
### Cisco IOS Client
~~~
aaa new-model
ip radius source-interface Loopback0

radius server aaa-server-1
 address ipv4 10.133.60.251 auth-port 1812 acct-port 1813
 key r1radiuskey
 exit
aaa group server radius aaa_group
 server name aaa-server-1
 exit

aaa authentication login vty_method group local aaa_group
aaa authorization exec default local group aaa_group

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
client r1.tapeitup.private {
	ipaddr = 10.133.2.1
  	secret = r1radiuskey
	shortname = r1
}
client sw3.tapeitup.private {
	ipaddr = 10.133.2.53
  	secret = sw3radiuskey
	shortname = sw3
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
### Testing (R!)
#### Command to initiate SSH Connection
~~~
ssh-keygen -f '$HOME/.ssh/known_hosts' -R '192.168.250.1' ; ssh -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256 -oCiphers=aes256-gcm@openssh.com,aes256-ctr,chacha20-poly1305@openssh.com -oMACs=hmac-sha2-512-etm@openssh.com john@192.168.250.1
~~~

#### Test Output
~~~
john@DEBTOP:~/gns3_gui$ ssh-keygen -f '/home/john/.ssh/known_hosts' -R '192.168.250.1' ; ssh -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256 -oCiphers=aes256-gcm@openssh.com,aes256-ctr,chacha20-poly1305@openssh.com -oMACs=hmac-sha2-512-etm@openssh.com john@192.168.250.1
# Host 192.168.250.1 found: line 45
/home/john/.ssh/known_hosts updated.
Original contents retained as /home/john/.ssh/known_hosts.old
The authenticity of host '192.168.250.1 (192.168.250.1)' can't be established.
RSA key fingerprint is SHA256:IQPt3XchrB8778Cy59HLhheC8AMRcijnvlR40GnvkEo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.250.1' (RSA) to the list of known hosts.
(john@192.168.250.1) Password: 
Radius john
r1#show version | include Version
Cisco IOS Software [Dublin], Linux Software (X86_64BI_LINUX-ADVENTERPRISEK9-M), Version 17.12.1, RELEASE SOFTWARE (fc5)
r1#
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

Im only running one device capable of restconf, r1.

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
