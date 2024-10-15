
# Variables
pass="ldap"
predot="tapeitup"
postdot="private"
domain="$predot.$postdot"

# Generate LDAP base DN and admin DN
base_dn="dc=$predot,dc=$postdot"
admin_dn="cn=admin,$base_dn"

ldapadd -x -D $admin_dn -w $pass -f /root/base.ldif
rm /root/base.ldif