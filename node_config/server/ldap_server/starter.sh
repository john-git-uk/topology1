#!/bin/bash
# Log file path
LOGFILE="/root/starter.log"
touch $LOGFILE
chmod 644 $LOGFILE

# Add a header and timestamp to the log file
echo "===== Service Startup Log =====" > $LOGFILE 2>&1
echo "Timestamp: $(date)" >> $LOGFILE 2>&1
echo "==============================" >> $LOGFILE 2>&1
echo "" >> $LOGFILE 2>&1

INTERFACES_UP=false

# Wait until eth1 and eth2 are up (with a timeout of 30 seconds)
for i in {1..30}; do
    if ip link show eth1 | grep -q "state UP" && ip link show eth2 | grep -q "state UP"; then
        echo "Interfaces are up" >> $LOGFILE 2>&1
        INTERFACES_UP=true
        break
    fi
    echo "Waiting for network interfaces to be up..." >> $LOGFILE 2>&1
    sleep 1
done

if [ "$INTERFACES_UP" = false ]; then
    echo "ERROR: Network interfaces eth1 and/or eth2 did not come up after 30 seconds." >> $LOGFILE 2>&1
fi

mkdir -p /sbin/scripts/flags
STATE_FILE="/sbin/scripts/flags/ranonce"

if [ -f "$STATE_FILE" ]; then
    echo "The runonce script has been run before." >> $LOGFILE 2>&1
    exit 0
else
    echo "Running the runonce script for the first time" >> $LOGFILE 2>&1
    bash /sbin/scripts/runonce.sh >> $LOGFILE 2>&1
    # Create the state file to indicate that the script has been run
    touch "$STATE_FILE" >> $LOGFILE 2>&1
    echo "ranonce set"  >> $LOGFILE 2>&1
fi

# Starting Services
rsyslogd >> $LOGFILE 2>&1
bash /sbin/scripts/networkconfig.sh >> $LOGFILE 2>&1
/etc/init.d/slapd start >> $LOGFILE 2>&1
sleep 2
LDAP_BUILD="/sbin/scripts/flags/ldapbuilt"
#debug
rm LDAP_BUILD
if [ -f "$LDAP_BUILD" ]; then
    echo "The ldap build script has been run before." >> $LOGFILE 2>&1
    exit 0
else
    echo "Running the ldap build script for the first time" >> $LOGFILE 2>&1
	bash /sbin/scripts/ldap_build.sh >> $LOGFILE 2>&1
	ldapmodify -Y EXTERNAL -H ldapi:/// -f /root/logging.ldif >> $LOGFILE 2>&1

    echo "ldapbuilt set"  >> $LOGFILE 2>&1
fi
/etc/init.d/ssh start >> $LOGFILE 2>&1
a2enmod rewrite >> $LOGFILE 2>&1
/etc/init.d/apache2 start >> $LOGFILE 2>&1
/etc/init.d/nslcd start >> $LOGFILE 2>&1
clear

# Launching shell
cd
exec bash -i

