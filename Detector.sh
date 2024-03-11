#/bin/bash

source Colors.sh
source Messages.sh

whitelist_file_4="./whitelist4.txt"
whitelist_file_6="./whitelist6.txt"
logs="./logs.txt"

layer2=1
layer7=1
ipv4=1
ipv6=1
incoming=1
outgoing=1

interfaces_list=$(ifconfig | awk '{print $1}' | grep ':' | tr -d ':')
interfaces=()

arg=$1
arg2=$3
arg3=$4
arg4=$5
pid_sniffer=""

general_capture=".general.pcap"

function killer() {
    
    kill $pid_sniffer
    for file in $(ls -a .*.pcap);
    do
	rm $file
    done
    exit
}

function builder_sniffer() {
    
    if [ "$layer7" -eq 0 ];
    then
	i=0
	default_filter="ether host ${your_mac} or host ${your_ip}"
	n_hosts="$(cat ${whitelist_file} | wc -l)"
	
	#Variables needed to exclude host traffic in whitelist
	init_keyword=""
	final_keyword=""
	wl_hosts=()
	
	if [ "${n_hosts}" -gt 0 ];
	then
	    init_keyword="and not("
            final_keyword=")"
	
	    for wl_host in $(cat $whitelist_file);
	    do
		if [ "$i" -lt 1 ];
		then
		    builder="host ${wl_host}"	    
		else
		    builder="or host ${wl_host}"
		fi
		wl_hosts+=($builder)
		i=$((i+1))
	    done
	fi
	new_filter="${default_filter} ${init_keyword} ${wl_hosts[*]} ${final_keyword}"
	
    elif [ "$layer2" -eq 0 ];
    then
	new_filter="not tcp and not udp"
    fi
}

function sniffer() {
    
    tshark -w "${general_capture}" -i $net_interface -f "${new_filter}" > /dev/null 2>&1 &
    pid_sniffer=$!
    #principal sniffer process ID
}

function show_help() {
    
    echo -e "${yellow}\n TTP Tracker V 1.0.0 - By: Luis Herrera${green}"
    echo -e "\n Usage: ./ttptracker.sh [INTERFACE] [LAYER_OPTIONS] [IP_OPTIONS] [ANALYZE_OPTIONS]"
    echo -e "\n\t -h, --help: Show this panel."
    echo -e "\n\t -l, --list-interfaces: Show available interfaces in your system."
    echo -e "\n\t -i, --interface: Establish a listening interface."
    echo -e "\n\t ${yellow}[LAYER OPTIONS] ${green}"
    echo -e "\n\t -l7, --layer7: Hunt in layer 7."
    echo -e "\n\t -l2, --layer2: Hunt in layer 2."
    echo -e "\n\t ${yellow}[IP OPTIONS] ${green}"
    echo -e "\n\t -6, --ipv6: Use IPv6 protocol."
    echo -e "\n\t -4, --ipv4: Use IPv4 protocol."
    echo -e "\n\t ${yellow}[ANALYZE OPTIONS] ${green}"
    echo -e "\n\t -in, --inbound: Analyze incoming traffic."
    echo -e "\n\t -out, --outbound: Analyze outgoing traffic.\n${default}"
}

function working_sessions() {

    sessions=()
    partials=()

    #List of protocolss where TTP Tracker performs threat hunting in l7 option
    l7_list=(
	'http'
	'ssl'
	'ssh'
	'ftp'
	'tftp'
	'dns'
	'smb2'
	'dcerpc'
	'ntlm'
	'kerberos'
	'smtp'
	'icmp'
	'icmpv6'
	'dhcp'
	'llmnr'
    )

    #List of protocolss where TTP Tracker performs threat hunting in l2 option
    l2_list=(
	'arp'
	'icmp'
	'icmpv6'
	'stp'
	'cdp'
	'lldp'
	'hsrp'
    )
    
    while true;
    do
	partial_session=0
	in="${#sessions[@]}"
	
	if [ "$incoming" -eq 0 ];
	then
            session=$(tshark -r "${general_capture}" -Y "ip.src != ${your_ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.srcport" 2> /dev/null)
	   
	elif [ "$outgoing" -eq 0 ];
	then
            session=$(tshark -r "${general_capture}" -Y "ip.src == ${your_ip} && tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.srcport" 2> /dev/null)
	fi

	sessions=($session)
	fin="${#sessions[@]}"

	if [ "${fin}" -ne "${in}" ];
	then
	    #All sessions
            for (( i="${in}";i<="$(( ${fin} - 1 ))";i++ ));
	    do
		sleep 1 
	        session_ready
	    done
	fi

	if [ "${#partials[@]}" -gt 0 ];
	then
	    #Partial sessions
	    partial_session=1
	    for (( i=0;i<="$(( ${#partials[@]} - 1 ))";i++ ));
	    do
		sleep 1
	        session_ready
	    done
	fi	
        sleep 3
    done
}

function session_ready() {

    if [ "$partial_session" -eq 1 ];
    then	
	port="${partials[$i]}"
    else
	port="${sessions[$i]}"
    fi

    #start session analysis
    timestamp=$(date | awk '{print $5}')
    conn_status
}

function show_message() {

    echo -e " [${timestamp}] ${1} ${socket}" >> $2
}

function conn_status() {

    flags=$(tshark -r "${general_capture}" -Y "tcp.port == ${port}" -T fields -e "tcp.flags" 2> /dev/null | sort | uniq | tr -d '0x')
    flags_array=($flags)

    if [ "$incoming" -eq 0 ];
    then
	impact_ip=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ip.src != ${your_ip}" -T fields -e "ip.src" 2> /dev/null | sort | uniq)
	impact_port=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ip.src != ${your_ip}" -T fields -e "tcp.dstport" 2> /dev/null | sort | uniq)

    elif [ "$outgoing" -eq 0 ];
    then
	impact_ip=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ip.dst != ${your_ip}" -T fields -e "ip.dst" 2> /dev/null | sort | uniq)
	impact_port=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ip.dst != ${your_ip}" -T fields -e "tcp.dstport" 2> /dev/null | sort | uniq)
    fi

    socket="[${impact_ip}:${impact_port}]"
    add=0
    finished=0
    unfinished=0
    syn=0
    synack=0
    ack=0
    fin=0
    rst=0

    for (( j=0;j<="$(( ${#flags_array[@]} - 1 ))";j++ ));
    do
	flag="${flags_array[$j]}"
	
        if [ "$flag" == "2" ];
	then
	    syn=1

	elif [ "$flag" == "12" ];
	then
	    synack=1

	elif [ "$flag" == "1" ];
	then
	    ack=1

	elif [ "$flag" == "11" ];
	then
	    fin=1

	elif [ "$flag" == "14" ];
	then
	    rst=1
	fi
    done

    if [[ ("$syn" -eq 1 && "$synack" -eq 1 && "$ack" -eq 1) &&
	  ("$fin" -eq 0 && "$rst" -eq 0) ]];
    then
	show_message "$T1" "$logs"
	unfinished=1
	partial_sessions
    fi
	
    if [[ ("$syn" -eq 1 && "$synack" -eq 1 && "$ack" -eq 1) &&
	  ("$fin" -eq 1 || "$rst" -eq 1) ]];
    then
	show_message "$T8" "$logs"
	if [ "$partial_session" -eq 1 ]; then finished=1; partial_sessions; fi
        for (( k=0;k<="$(( ${#l7_list[@]} - 1 ))";k++ ));
        do
            n_service=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ${l7_list[$k]}" 2> /dev/null | wc -l)
            if [ "$(( n_service ))" -gt 0 ];
            then
		service="${l7_list[$k]}"
		begin_threat_hunt_l7
	    fi
	done
    fi

    if [[ "$syn" -eq 1 &&
	  "$synack" -eq 0 ]];
    then
        show_message "$T2" "$logs"
    fi

    if [[ "$syn" -eq 1 &&
	  "$synack" -eq 0 &&
	  "$rst" -eq 1 ]];
    then
	show_message "$T3" "$logs"
    fi
}

function partial_sessions() {

    if [ "${#partials[@]}" -gt 0 ];
    then
	for (( k=0;k<="$(( ${#partials[@]} - 1 ))";k++ ));
	do
	    if [[ "$port" != "${partials[$k]}" &&
		  "$unfinished" -eq 1 ]];
	    then
		add=$((add+1))
	    fi
	
	    if [[ "$port" == "${partials[$k]}" &&
		  "$finished" -eq 1 ]];
	    then
		unset "partials[k]"
		break
	    fi
	done
    fi

    if [[ ("${#partials[@]}" -lt 1 && "$unfinished" -eq 1) ||
	  ("$(( add - 1 ))" -eq "$(( ${#partials[@]} - 1 ))") ]];
    then
	partials+=($port)
    fi
}

function begin_threat_hunt_l7() {

    extensions=('.exe' '.zip' '.msi' '.dll' '.bat' '.py' '.jpg' '.png' '.pdf' '.docx' '.xls' '.gif' '/')
    
    if [ "$service" == "http" ];
    then
	methods=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && http.request.method" -T fields -e "http.request.method" 2> /dev/null)
        uri=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && http.request.uri" -T fields -e "http.request.uri" 2> /dev/null)
	mime_types=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && http.content_type" -T fields -e "http.content_type" 2> /dev/null)
	status_codes=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && http.response.code" -T fields -e "http.response.code" 2> /dev/null)
	
	for (( i=0;i<="$(( ${#extensions[@]} - 1 ))";i++ ));
	do
	    if [[ "$uri" =~ "${extensions[$i]}" ]];
	    then
		show_message "$H1" "$logs"
		break
            fi
	done
    fi
 }

if [ "$(id -u)" == "0" ];
then
    if [ "$arg" == "--help" ] ||
       [ "$arg" == "-h" ]
    then
	show_help
        exit
	
    elif  [ "$arg" == "--list-interfaces" ] ||
	  [ "$arg" == "-l" ]
    then
        interfaces=($interfaces_list)
	echo -e "${yellow}\n Available interfaces:\n"
	for (( i=0;i<="$(( ${#interfaces[@]} - 1 ))";i++ ));
	do
	    echo -e "${green} [+] ${interfaces[$i]}${default}\n"
	done
	
    elif [ "$arg" == "--interface" ] ||
	 [ "$arg" == "-i" ]
    then
	start_l7=0
	start_l2=0
	interface=0
        net_interface=$2
        interfaces=($interfaces_list)
	
	for (( i=0;i<="$(( ${#interfaces[@]} - 1 ))";i++ ));
	do
	    if [ "$net_interface" == "${interfaces[$i]}" ];
	    then
		break
	    else
	        interface=$((interface+1))
	    fi
	done
	
	if [ "$interface" -lt "$(( ${#interfaces[@]} - 1 ))" ];
	then
	    start_l7=$((start_l7+1))
	    start_l2=$((start_l2+1))
	fi
	
	if [ "$arg2" == "--layer7" ] ||
	   [ "$arg2" == "-l7" ]
        then
	    start_l7=$((start_l7+1))
	    layer7=0
	   
	    if [ "$arg3" == "-6" ] ||
	       [ "$arg3" == "--ipv6" ]
	    then
	        start_l7=$((start_l7+1))
	        ipv6=0
		
	    elif [ "$arg3" == "-4" ] ||
		 [ "$arg3" == "--ipv4" ]
	    then
	        start_l7=$((start_l7+1))
	        ipv4=0
	    fi
	    
	elif [ "$arg2" == "--layer2" ] ||
	     [ "$arg2" == "-l2" ]
	then
	    start_l2=$((start_l2+1))
	    layer2=0
	fi
	
	if [ "$arg4" == "--incoming" ] ||
	   [ "$arg4" == "-in" ]
	then
	    start_l2=$((start_l2+1))
	    start_l7=$((start_l7+1))
	    incoming=0
	    
	elif [ "$arg4" == "--outgoing" ] ||
	     [ "$arg4" == "-out" ];
	then
	    start_l2=$((start_l2+1))
	    start_l7=$((start_l7+1))
	    outgoing=0
	fi
	   
	if [[ "$start_l7" -eq 4 ||
	      "$start_l2" -eq 3 ]];
	then
	    echo -e "${green}\n [+] Loading, wait a moment....${default}"
	    sleep 5
	   
	    if [ "$ipv4" -eq 0 ];
	    then
		your_ip=$(ifconfig $net_interface | grep -w 'inet' | awk '{print $2}')
		whitelist_file=$whitelist_file_4
		
	    elif [ "$ipv6" -eq 0 ];
	    then
		your_ip=$(ifconfig $net_interface | grep -w 'inet6' | awk '{print $2}')
		whitelist_file=$whitelist_file_6
	    fi
	   
	    your_mac=$(ifconfig $net_interface | grep 'eth' | awk '{print $2}')
	    
	    trap killer SIGINT
	    clear
	    builder_sniffer
	    sniffer
	    echo -e "${green}\n [+] I'm Hunting....${default}"
	    
	    if [ "$layer7" -eq 0 ];
	    then
		working_sessions
		
	    elif [ "$layer2" -eq 0];
	    then
		hunt_l2
	    fi
	else
	    echo -e "${red}\n ${err_args}${default}"
	    sleep 2
	    show_help
	fi
    else
        show_help
        exit
    fi
else
    echo -e "${red}\n ${err_root} ${default}\n"
    sleep 5
fi

