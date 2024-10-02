# Log file path
LOGFILE="/root/starter.log"
touch $LOGFILE
chmod 644 $LOGFILE

# Add a header and timestamp to the log file
echo "===== Service Startup Log =====" > $LOGFILE
echo "Timestamp: $(date)" >> $LOGFILE
echo "==============================" >> $LOGFILE
echo "" >> $LOGFILE

# Wait until eth1 and eth2 are up (with a timeout of 30 seconds)
for i in {1..30}; do
    if ip link show eth1 up && ip link show eth2 up; then
        echo "Interfaces are up" >> $LOGFILE
        INTERFACES_UP=true
        break
    fi
    echo "Waiting for network interfaces to be up..." >> $LOGFILE
    sleep 1
done

if [ "$INTERFACES_UP" = false ]; then
    echo "ERROR: Network interfaces eth1 and/or eth2 did not come up after 30 seconds." >> $LOGFILE
fi

# Starting Services
rsyslogd >> $LOGFILE 2>&1

bash /root/networkconfig.sh >> $LOGFILE

/etc/init.d/freeradius start >> $LOGFILE 2>&1
/etc/init.d/tacacs_plus start >> $LOGFILE 2>&1
/etc/init.d/ssh start >> $LOGFILE 2>&1
clear

# Launching shell
cd
exec bash -i

