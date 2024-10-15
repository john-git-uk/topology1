#!/bin/bash

# Variables
pass="ldap"
predot="tapeitup"
postdot="private"
domain="$predot.$postdot"

# Generate LDAP base DN and admin DN
base_dn="dc=$predot,dc=$postdot"
admin_dn="cn=admin,$base_dn"

# Set debconf for non interactive setup
echo "slapd slapd/internal/generated_adminpw password $pass" | debconf-set-selections
echo "slapd slapd/internal/adminpw password $pass" | debconf-set-selections
echo "slapd slapd/password2 password $pass" | debconf-set-selections
echo "slapd slapd/password1 password $pass" | debconf-set-selections
echo "slapd slapd/domain string $domain" | debconf-set-selections
echo "slapd shared/organization string \"$predot\"" | debconf-set-selections

dpkg-reconfigure -f noninteractive slapd