
chmod 755 /sbin/scripts/starter.sh
chmod 755 /sbin/scripts/ldap_init.sh
bash /sbin/scripts/ldap_setup.sh
mkdir -p /run/sshd
chmod 0755 /run/sshd
echo "libpam-runtime libpam-runtime/profiles multiselect unix, ldap, create-home" | debconf-set-selections
pam-auth-update --package