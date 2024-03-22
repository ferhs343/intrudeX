#/bin/bash

# +------------------------------------------------------------------------+
# | TTP Tracker                                                            |
# | -----------                                                            |
# |                                                                        |
# | Threat hunting endpoint tool in search of TTP in the network traffic.  |
# |                                                                        |
# | Author: Luis Herrera - @Ferhs343                                       |
# | Contact: fer.hs343@gmail.com                                           |
# | V 1.0.0                                                                |
# |                                                                        |
# +------------------------------------------------------------------------+

source Colors.sh
source Messages.sh
source Files.sh

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

    tcp_sessions=()
    udp_sessions=()
    partials=()
    
    #List of TCP protocolss where TTP Tracker performs threat hunting in l7 option
    tcp_list=(
	'http'          #INCOMING/OUTGOING MODE
	'ssl'           #INCOMING/OUTGOING MODE
	'ssh'           #INCOMING/OUTGOING MODE
	'ftp'           #INCOMING/OUTGOING MODE
	'smb2'          #ONLY OUTGOING MODE
	'dcerpc'        #ONLY OUTGOING MODE
	'ntlm'          #ONLY OUTGOING MODE
	'kerberos'      #ONLY OUTGOING MODE
	'smtp'          #INCOMING/OUTGOING MODE
	'llmnr'         #ONLY OUTGOING MODE
    )

    #List of UDP protocolss where TTP Tracker performs threat hunting in l7 option
    udp_list=(
	'llmnr'
	'dcerpc'
	'kerberos'
	'tftp'          #INCOMING/OUTGOING MODE
	'dns'           #INCOMING/OUTGOING MODE
	'dhcp'          #ONLY OUTGOING MODE
	'dhcpv6'        #ONLY OUTGOING MODE
    )

    auxiliar_list=(
	'icmp'          #INCOMING/OUTGOING MODE
	'icmpv6'        #INCOMING/OUTGOING MODE
    )
    
    #List of protocolss where TTP Tracker performs threat hunting in l2 option
    l2_list=(
	'arp'           #INCOMING/OUTGOING MODE
	'icmp'          #INCOMING/OUTGOING MODE
	'icmpv6'        #INCOMING/OUTGOING MODE
	'stp'           #ONLY OUTGOING MODE
	'cdp'           #ONLY OUTGOING MODE
	'lldp'          #ONLY OUTGOING MODE
	'hsrp'          #ONLY OUTGOING MODE
    )
    
    while true;
    do
	if [ "$((alternate % 2))" -eq 0 ];
	then
	    tcp=1
	    udp=0
	    session_filter="tcp.flags.syn == 1 && tcp.flags.ack == 0"
	    port_filter="tcp.srcport"
	else
	    udp=1
	    tcp=0
	    session_filter="udp"
	    port_filter="udp.srcport"
	fi
	
	partial_session=0
	if [ "$tcp" -eq 1 ]; then ini="${#tcp_sessions[@]}"; else ini="${#udp_sessions[@]}"; fi
						
	if [ "$incoming" -eq 0 ];
	then
            session=$(tshark -r "${general_capture}" -Y "${ip_filter}.src != ${your_ip} && ${session_filter}" -T fields -e "${port_filter}" 2> /dev/null)
	   
        elif [ "$outgoing" -eq 0 ];
	then
            session=$(tshark -r "${general_capture}" -Y "${ip_filter}.src == ${your_ip} && ${session_filter}" -T fields -e "${port_filter}" 2> /dev/null)
	fi

        if [ "$tcp" -eq 1 ]; then tcp_sessions=($session); else udp_sessions=($session); fi
	if [ "$tcp" -eq 1 ]; then fin="${#tcp_sessions[@]}"; else fin="${#udp_sessions[@]}"; fi
	
	if [ "${fin}" -ne "${ini}" ];
	then
	    #All sessions
            for (( i="${ini}";i<="$(( ${fin} - 1 ))";i++ ));
	    do
	        prepare_session
	    done
	fi

	if [[ "${#partials[@]}" -gt 0 &&
	      "$tcp" -eq 1 ]];
	then
	    #Partial sessions
	    partial_session=1
	    for (( i=0;i<="$(( ${#partials[@]} - 1 ))";i++ ));
	    do
	        prepare_session
	    done
	fi
	
        sleep 3
	alternate=$((alternate+1))
    done
}

function prepare_session() {

    #start session analysis
    timestamp=$(date | awk '{print $2 " " $3 " " $4 " " $5}')

    if [ "$partial_session" -eq 1 ];
    then	
	port="${partials[$i]}"
    else
	if [ "$tcp" -eq 1 ]; then port="${tcp_sessions[$i]}"; else port="${udp_sessions[$i]}"; fi
    fi

    if [ "$tcp" -eq 1 ]; then tcp_extract_info; else udp_extract_info; fi
}

function show_message() {

    echo -e " ${timestamp} ${socket} ${2} ${3} ${4} ${5} ${6}" >> $1
}

function tcp_extract_info() {

    path_log="./$logs_dir/${logs[0]}"
    flags=$(tshark -r "${general_capture}" -Y "tcp.port == ${port}" -T fields -e "tcp.flags" 2> /dev/null | sort | uniq | tr -d '0x')
    flags_array=($flags)

    if [ "$incoming" -eq 0 ];
    then
	impact_ip=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ${ip_filter}.src != ${your_ip}" -T fields -e "${ip_filter}.src" 2> /dev/null | sort | uniq)
	impact_port=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ${ip_filter}.src != ${your_ip}" -T fields -e "tcp.dstport" 2> /dev/null | sort | uniq)

    elif [ "$outgoing" -eq 0 ];
    then
	impact_ip=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ${ip_filter}.dst != ${your_ip}" -T fields -e "${ip_filter}.dst" 2> /dev/null | sort | uniq)
	impact_port=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ${ip_filter}.dst != ${your_ip}" -T fields -e "tcp.dstport" 2> /dev/null | sort | uniq)
    fi

    socket="${impact_ip}:${impact_port}"
    add=0
    finished=0
    unfinished=0
    #TCP Flags
    SY=0
    SA=0
    AK=0
    FN=0
    RT=0

    for (( j=0;j<="$(( ${#flags_array[@]} - 1 ))";j++ ));
    do
	flag="${flags_array[$j]}"
	
        if [ "$flag" == "2" ];
	then
            SY=1

	elif [ "$flag" == "12" ];
        then
	    SA=1

	elif [ "$flag" == "1" ];
	then
	    AK=1

	elif [ "$flag" == "11" ];
	then
	    FN=1

	elif [ "$flag" == "14" ];
	then
	    RT=1
	fi
    done

    if [[ ("$SY" -eq 1 && "$SA" -eq 1 && "$AK" -eq 1) &&
	  ("$FN" -eq 0 && "$RT" -eq 0) ]];
    then
	if [ "$partial_session" -eq 0 ];
	then
	    show_message "$path_log" "$T1"
	    unfinished=1
	    partial_sessions
	fi
    fi
	
    if [[ ("$SY" -eq 1 && "$SA" -eq 1 && "$AK" -eq 1) &&
	  ("$FN" -eq 1 || "$RT" -eq 1) ]];
    then
	show_message "$path_log" "$T4" 
	if [ "$partial_session" -eq 1 ]; then finished=1; partial_sessions; fi
        for (( k=0;k<="$(( ${#tcp_list[@]} - 1 ))";k++ ));
        do
            n_service=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && ${tcp_list[$k]}" 2> /dev/null | wc -l)
            if [ "$(( n_service ))" -gt 0 ];
            then
		service="${tcp_list[$k]}"
		tcp_services_log
	    fi
	done
    fi

    if [[ "$SY" -eq 1 &&
	  "$SA" -eq 0 &&
	  "$RT" -eq 0 &&
	  "$FN" -eq 0 ]];
    then
        show_message "$path_log" "$T2" 
    fi

    if [[ "$SY" -eq 1 &&
	  "$SA" -eq 0 &&
	  "$RT" -eq 1 ]];
    then
	show_message "$path_log" "$T3"
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

function udp_extract_info() {

    path_log="./$logs_dir/${logs[0]}"

    if [ "$incoming" -eq 0 ];
    then
	impact_ip=$(tshark -r "${general_capture}" -Y "udp.port == ${port} && ${ip_filter}.src != ${your_ip}" -T fields -e "${ip_filter}.src" 2> /dev/null | sort | uniq)
	impact_port=$(tshark -r "${general_capture}" -Y "udp.port == ${port} && ${ip_filter}.src != ${your_ip}" -T fields -e "udp.dstport" 2> /dev/null | sort | uniq)

    elif [ "$outgoing" -eq 0 ];
    then
	impact_ip=$(tshark -r "${general_capture}" -Y "udp.port == ${port} && ${ip_filter}.dst != ${your_ip}" -T fields -e "${ip_filter}.dst" 2> /dev/null | sort | uniq)
	impact_port=$(tshark -r "${general_capture}" -Y "udp.port == ${port} && ${ip_filter}.dst != ${your_ip}" -T fields -e "udp.dstport" 2> /dev/null | sort | uniq)
    fi

    socket="${impact_ip}:${impact_port}"

    show_message "$path_log" "$U1"
    for (( k=0;k<="$(( ${#udp_list[@]} - 1 ))";k++ ));
    do
	n_service=$(tshark -r "${general_capture}" -Y "udp.port == ${port} && ${udp_list[$k]}" 2> /dev/null | wc -l)
        if [ "$(( n_service ))" -gt 0 ];
        then
	    service="${udp_list[$k]}"
	    udp_services_log
	fi
    done
}

function udp_services_log() {

    if [ "$service" == "dns" ];
    then
	path_log="./$logs_dir/${logs[7]}"
	query=$(tshark -r "${general_capture}" -Y "udp.port == ${port} && dns.qry.name" -T fields -e "dns.qry.name" 2> /dev/null)
	response_t=$(tshark -r "${general_capture}" -Y "udp.port == ${port} && dns.resp.type" -T fields -e "dns.resp.type" 2> /dev/null)
	response_n=$(tshark -r "${general_capture}" -Y "udp.port == ${port} && dns.resp.name" -T fields -e "dns.resp.name" 2> /dev/null)
	show_message "$path_log" "$query" "$response_t" "$response_n"
    fi
}

function tcp_services_log() {
    
    if [ "$service" == "http" ];
    then
	path_log="./$logs_dir/${logs[1]}"
	method=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && http.request.method" -T fields -e "http.request.method" 2> /dev/null)
        uri=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && http.request.uri" -T fields -e "http.request.uri" 2> /dev/null)
	user_agent=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && http.user_agent" -T fields -e "http.user_agent" 2> /dev/null)
        mime_type=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && http.content_type" -T fields -e "http.content_type" 2> /dev/null)
	status_code=$(tshark -r "${general_capture}" -Y "tcp.port == ${port} && http.response.code" -T fields -e "http.response.code" 2> /dev/null)
        show_message "$path_log" "$method" "$uri" "$user_agent" "$mime_type" "$status_code"

    elif [ "$service" == "ssl" ];
    then
	o=0
    fi
}

if [ "$(id -u)" == "0" ];
then
    logs=()
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
	    logs=("${in_logs[@]}")
	    incoming=0
	    
	elif [ "$arg4" == "--outgoing" ] ||
	     [ "$arg4" == "-out" ];
	then
	    start_l2=$((start_l2+1))
	    start_l7=$((start_l7+1))
	    logs=("${out_logs[@]}")
	    outgoing=0
	fi
	   
	if [[ "$start_l7" -eq 4 ||
	      "$start_l2" -eq 3 ]];
	then
	    echo -e "${green}\n [+] Loading, wait a moment....${default}"
	    sleep 5

	    for (( i=0;i<="$(( ${#logs[@]} - 1 ))";i++ ));
	    do
		if [[ ! -f "./$logs_dir/${logs[$i]}" ]];
		then
		    touch "./$logs_dir/${logs[$i]}"
		fi
	    done
	    
	    if [ "$ipv4" -eq 0 ];
	    then
		your_ip=$(ifconfig $net_interface | grep -w 'inet' | awk '{print $2}')
		whitelist_file=$whitelist_file_4
	        ip_filter="ip"
		
	    elif [ "$ipv6" -eq 0 ];
	    then
		your_ip=$(ifconfig $net_interface | grep -w 'inet6' | awk '{print $2}')
	        whitelist_file=$whitelist_file_6
		ip_filter="ipv6"
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
