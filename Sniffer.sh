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
source Protocols.sh

layer2=1
layer7=1
incoming=1
outgoing=1

interfaces_list=$(ifconfig | awk '{print $1}' | grep ':' | tr -d ':')
interfaces=()

arg=$1
arg2=$3
arg3=$4
arg4=$5
arg5=$6
pid_sniffer=""

function killer() {

    echo -e "\n Process disrupted, exiting.... "
    kill $pid_sniffer
    
    for file in $(ls -a .*.pcap.gz);
    do
	rm $file
    done
    
    sleep 3
    exit
}

function builder_filters() {
    
    if [ "$layer7" -eq 0 ];
    then	
        parts=()
	j=0
        n_elements="$(cat ${filter_files[$i]} | wc -l)"
	
	if [ "$n_elements" -gt 1 ];
	then
	    init_keyword="and not("
	    final_keyword=")"
	    for element in $(cat "${filter_files[$i]}" | grep -v "#");
	    do
	        if [[ "${filter_files[$i]}" =~ "./host_filter" ]];
	        then
	            if [ "$j" -lt 1 ];
		    then
		        part="host ${element}"
		    else
		        part="or host ${element}"
		    fi

		elif [ "${filter_files[$i]}" == "./service_filter.txt" ];
	        then
	      	    if [ "$j" -lt 1 ];
		    then
		        part="${element}"
		    else
		        part="or ${element}"
		    fi

		elif [ "${filter_files[$i]}" == "./domain_filter.txt" ];
	        then
		    if [ "$j" -lt 1 ];
		    then
		        part="dns.qry.name == ${element}"
		    else
		        part="or dns.qry.name == ${element}"
		    fi
		fi

		parts+=($part)
	        j=$((j+1))
	    done
	else
	    init_keyword=""
	    final_keyword=""
	fi
	
    elif [ "$layer2" -eq 0 ];
    then
	default_general_filter="not tcp and not udp"
    fi
}

function sniffer() {

    touch $general_capture
    gzip $general_capture
    general_capture="${general_capture}.gz"
    tshark -w "${general_capture}" -i $net_interface -f "${default_general_filter}" > /dev/null 2>&1 &
    pid_sniffer=$!
    #principal sniffer process ID
}

function show_help() {
    
    echo -e "${yellow}\n TTP Tracker V 1.0.0 - By: Luis Herrera${green}"
    echo -e "\n Usage: ./ttptracker.sh [INTERFACE] [LAYER_OPTIONS] [IP_OPTIONS] [ANALYZE_OPTIONS] [HUNT_OPTIONS]"
    echo -e "\n\t -h, --help: Show this panel."
    echo -e "\n\t -l, --list-interfaces: Show available interfaces in your system."
    echo -e "\n\t -i, --interface: Establish a listening interface."
    echo -e "\n\t ${yellow}[LAYER OPTIONS] ${green}"
    echo -e "\n\t -l7, --layer7: Work in layer 7."
    echo -e "\n\t -l2, --layer2: Work in layer 2."
    echo -e "\n\t ${yellow}[IP OPTIONS] ${green}"
    echo -e "\n\t -6, --ipv6: Use IPv6 protocol."
    echo -e "\n\t -4, --ipv4: Use IPv4 protocol."
    echo -e "\n\t ${yellow}[ANALYZE OPTIONS] ${green}"
    echo -e "\n\t -in, --inbound: Incoming traffic."
    echo -e "\n\t -out, --outbound: Outgoing traffic."
    echo -e "\n\t ${yellow}[HUNT OPTIONS] ${green}"
    echo -e "\n\t -hunt, --only-hunter: Execute tool only in hunter mode."
    echo -e "\n\t -log, --only-logs: Only generate traffic logs."
    echo -e "\n\t -all, --execute-all: Generate traffic logs and execute hunter mode.\n${default}"
}

function sessions() {

    tcp_streams=()
    udp_streams=()
    partials=()
    turn=0

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
	if [ "$((turn % 2))" -eq 0 ];
	then
	    tcp=1
	    udp=0
	    stream_filter="tcp.stream"
	else
	    udp=1
	    tcp=0
	    stream_filter="udp.stream"
	fi

	mechanism_one=0
	partial_session=0
	if [ "$tcp" -eq 1 ]; then ini="${#tcp_streams[@]}"; else ini="${#udp_streams[@]}"; fi

	if [ "$tcp" -eq 1 ];
	then
            session=$(tshark -r "${general_capture}" -Y "tcp" -T fields -e "${stream_filter}" 2> /dev/null | sort -n | uniq)
	else
	    session=$(tshark -r "${general_capture}" -Y "udp" -T fields -e "${stream_filter}" 2> /dev/null | sort -n | uniq)
	fi
	
        if [ "$tcp" -eq 1 ]; then tcp_streams=($session); else udp_streams=($session); fi
	if [ "$tcp" -eq 1 ]; then fin="${#tcp_streams[@]}"; else fin="${#udp_streams[@]}"; fi
	
	if [ "${fin}" -ne "${ini}" ];
	then
	    if [ "$((fin - ini))" -gt 5 ];
	    then
		#Begin log mechanism 1
		# > 5 streams per turn
		mechanism_one=1
	        mechanism_one
	    else
		#Begin log mechanism 2
		# < 5 streams per turn
		for (( i="${ini}";i<="$(( ${fin} - 1 ))";i++ ));
		do
		    sleep 0.3
	            mechanism_two
		done
	    fi
	fi

	if [[ "${#partials[@]}" -gt 0 &&
	      "$tcp" -eq 1 ]];
	then
	    #Partial sessions
	    partial_session=1
	    for (( i=0;i<="$(( ${#partials[@]} - 1 ))";i++ ));
	    do
		sleep 0.3
	        prepare_session
	    done
	fi

	sleep 2
	turn=$((turn+1))
    done
}

function mechanism_one() {
    
    if [ "$tcp" -eq 1 ];
    then
	stream_init="${tcp_streams[$ini - 1]}"
	stream_fin="${tcp_streams[$fin - 1]}"
	fast_tcp "$aux_filter" "$stream_init" "$stream_fin" "$procesing_logs"	
    else
	stream_init="${udp_streams[$ini - 1]}"
	stream_fin="${udp_streams[$fin - 1]}"
        fast_udp "$aux_filter" "$stream_init" "$stream_fin" "$procesing_logs"
    fi

    n=$(cat $procesing_logs | wc -l)
    if [ "$((n))" -lt 500 ];
    then
        file=$procesing_logs
	if [ "$tcp" -eq 1 ];
	then
            tcp_extract_info
	else
	    udp_extract_info
	fi
    else
        split $procesing_logs -l 500 trim
        mv trim* $logs_dir/$logs_in_process
	    
        for file in $(ls $logs_dir/$logs_in_process/trim*);
        do
	    if [ "$tcp" -eq 1 ];
	    then
      		tcp_extract_info
	    else
		udp_extract_info
	    fi
	    rm $file
	done
    fi
}

function mechanism_two() {
    
    if [ "$tcp" -eq 1 ]; then stream="${tcp_streams[$i]}"; else stream="${udp_streams[$i]}"; fi
    src=$(tshark -r "${general_capture}" -Y "${stream_filter} eq ${stream}" -T fields -e "${ip_filter}.src" 2> /dev/null | head -n 1)
    
    if [[ ("$src" == "${your_ip}" && "$outgoing" -eq 0) ||
	  ("$src" != "${your_ip}" && "$incoming" -eq 0) ]];
    then
	prepare_session
    fi
}

function prepare_session() {

    if [ "$partial_session" -eq 1 ]; then stream="${partials[$i]}"; fi
    timestamp=$(tshark -r "${general_capture}" -Y "${stream_filter} eq ${stream}" -T fields -e "frame.time" 2> /dev/null | head -n 1 | tr ' ' '-')
    if [ "$tcp" -eq 1 ]; then tcp_extract_info; else udp_extract_info; fi
}

function used_service() {

    service_list=("$@")
    for (( k=0;k<="$(( ${#service_list[@]} - 1 ))";k++ ));
    do
       n_service=$(tshark -r "${general_capture}" -Y "${stream_filter} eq ${stream} && ${service_list[$k]}" 2> /dev/null | wc -l)
       if [ "$((n_service))" -gt 0 ];
       then
	   service="${service_list[$k]}"
	   if  [ "$tcp" -eq 1 ];
	   then
	       tcp_services_log
	   else
	       udp_services_log
	   fi
        fi
    done
}

function preparing_log() {

    log_data=("$@")
    log="[${stream}] [${timestamp}]"

    for (( m=0;m<="$(( ${#log_data[@]} - 1 ))";m++ ));
    do
        log+=" [${log_data[$m]}]"
    done
}

function print_log() {

    echo "${log}" >> $1
}

function tcp_extract_info() {

    path_log="./$logs_dir/${logs[0]}"

    flags_history=""
    #TCP Flags
    SY=0
    SA=0
    AK=0
    PSH=0
    FN=0
    RT=0
    URG=0
    flags=()

    if [ "$mechanism_one" -eq 1 ];
    then
	for stream in $(cat $file | awk '{print $1}' | sort -n -u);
	do
	    extract_flags=$(cat $file | awk "\$1 == \"$stream\" {print \$NF}" | sort -u | awk '{print substr($0,length($0)-1)}')
	    flags=($extract_flags)
	    timestamp=$(awk -F'\t' -v stream=$stream '$1 == stream {print $2}' $file | head -n 1 | tr ' ' '-')

	    for (( j=0;j<="$(( ${#flags[@]} - 1 ))";j++ ));
	    do
		if [ "${flags[$j]}" == "02" ];
		then
		    SY=1
		    flags_history+="Syn "
		fi

		if [ "${flags[$j]}" == "12" ];
		then
		    SA=1
		    flags_history+="Synack "
		fi

		if [ "${flags[$j]}" == "18" ];
		then
		    PSH=1
		    flags_history+="Psh "
		fi
		
		if [ "${flags[$j]}" == "11" ];
		then
		    FN=1
		    flags_history+="Fin "
		fi 
	    done

	    awk -F'\t' -v stream="$stream" -v flags="$flags_history" -v ts="$timestamp" '$1 == stream && ($3 == "68:1d:ef:37:46:d3" || $4 == "10.30.1.79") {print "["$1"] " "["ts"] " "["$3"] " "["$4"] " "["$5"] " "["$6"] " "["$7"] " "["$8"] " "["flags"]"}' $file | sort -u >> $path_log
	    flags_history=""
	done
    else
	
	if [ "$(tshark -r ${general_capture} -Y \
             "tcp.stream eq ${stream} && tcp.flags.syn == 1" \ 
             2>/dev/null | wc -l)" -gt 0 ];
	then
            SY=1
            flags_history+="Syn"
	fi
	
	if [ "$(tshark -r ${general_capture} -Y \
             "tcp.stream eq ${stream} && tcp.flags.syn == 1 && tcp.flags.ack == 1" \
             2>/dev/null | wc -l)" -gt 0 ];
	then
            SA=1
            flags_history+="Synack"
	fi
	    
	if [ "$(tshark -r ${general_capture} -Y \
             "tcp.stream eq ${stream} && tcp.flags.syn == 0 && tcp.flags.ack == 1" \ 
             2>/dev/null | wc -l)" -gt 0 ];
	then
            AK=1
            flags_history+="Ack"
	fi

	if [ "$(tshark -r ${general_capture} -Y \
             "tcp.stream eq ${stream} && tcp.flags.push == 1" \
             2>/dev/null | wc -l)" -gt 0 ];
	then
            PSH=1
            flags_history+="Psh"
	fi
	
	if [ "$(tshark -r ${general_capture} -Y \
             "tcp.stream eq ${stream} &&  tcp.flags.fin == 1"\
              2>/dev/null | wc -l)" -gt 0 ];
	then
            FN=1
            flags_history+="Fin"
	fi
	
	if [ "$(tshark -r ${general_capture} -Y \
             "tcp.stream eq ${stream} && tcp.flags.rst == 1" \ 
             2>/dev/null | wc -l)" -gt 0 ];
	then
            RT=1
            flags_history+="Rst"
	fi

	if [ "$(tshark -r ${general_capture} -Y \
             "tcp.stream eq ${stream} && tcp.flags.urg == 1" \
             2>/dev/null | wc -l)" -gt 0 ];
	then
            URG=1
            flags_history+="Urg"
	fi

	tcp_conn_status
    fi
}

function tcp_conn_status() {
      
    tcp "$stream" "$aux_filter"
    if [ "$partial_session" -eq 0 ];
    then
	data=("$src_mac" "$src_ip" "$src_port" "$dst_mac" "$dst_ip" "$dst_port"  "$flags_history")
	preparing_log "${data[@]}"
	print_log "$path_log"
    fi
	
    if [[ ("$SY" -eq 1 && "$SA" -eq 1 && "$AK" -eq 1) &&
	  ("$FN" -eq 0 && "$RT" -eq 0) ]];
    then
	if [ "$partial_session" -eq 0 ];
	then
	    partials+=($stream)
	fi
    fi
    
    if [[ ("$SY" -eq 1 && "$SA" -eq 1 && "$AK" -eq 1) &&
	  ("$FN" -eq 1 || "$RT" -eq 1) ]];
    then
	if [ "$partial_session" -eq 1 ];
	then
	    timestamp=$(tshark -r "${general_capture}" -Y "${stream_filter} eq ${stream}" -T fields -e "frame.time" 2> /dev/null | tail -n 1 | tr ' ' '-');  
	    data=("$src_mac" "$src_ip" "$src_port" "$dst_mac" "$dst_ip" "$dst_port"  "$flags_history")
	    preparing_log "${data[@]}"
	    print_log "$path_log"
	fi

	used_service "${tcp_list[@]}"
	if [ "$partial_session" -eq 1 ];
	then
	    for (( k=0;k<="$(( ${#partials[@]} - 1 ))";k++ ));
	    do
		if [ "$stream" == "${partials[$k]}" ];
		then
		    unset "partials[$k]"
		    break
		fi
	    done
	fi
    fi
}

function udp_extract_info() {

    path_log="./$logs_dir/${logs[0]}"

    if [ "$mechanism_one" -eq 1 ];
    then
	for stream in $(cat $file | awk '{print $1}' | sort -n -u);
	do
	    timestamp=$(awk -F'\t' -v stream=$stream '$1 == stream {print $2}' $file | head -n 1 | tr ' ' '-')
	    awk -F'\t' -v stream="$stream" -v ts="$timestamp" -v msg="$U1" '$1 == stream && ($3 == "68:1d:ef:37:46:d3" || $4 == "10.30.1.79") {print "["$1"] " "["ts"] " "["$3"] " "["$4"] " "["$5"] " "["$6"] " "["$7"] " "["$8"] " "["msg"]"}' $file | sort -u >> $path_log
	done
    else
	
	udp "$stream" "$aux_filter" 
	data=("$src_mac" "$src_ip" "$src_port" "$dst_mac" "$dst_ip" "$dst_port" "$U1")
	preparing_log "${data[@]}"
	print_log "$path_log"
	used_service "${udp_list[@]}"
    fi
}

function udp_services_log() {

    if [ "$service" == "dns" ];
    then
	path_log="./$logs_dir/${logs[7]}"
	dns "$stream"
	query=($query)
	r_a=($r_a)
	r_aaaa=($r_aaaa)
	r_txt=($r_txt)
	c_name=($c_name)

	for (( l=0;l<="$(( ${#query[@]} - 1 ))";l++ ));
	do
            data=("${query[$l]}" "${r_a[$l]}" "${r_aaaa[$l]}" "${r_txt[$l]}" "${c_name[$l]}")
            preparing_log "${data[@]}"
	    print_log "$path_log"
	done
    fi
}

function tcp_services_log() {
    
    if [ "$service" == "http" ];
    then
	path_log="./$logs_dir/${logs[1]}"
        http "$stream"
	uri=($uri)
	method=($method)
	hostname=($hostname)
	user_agent=($user_agent)
	mime_type_rq=($mime_type_rq)
	mime_type_rp=($mime_type_rp)
	status_code=($status_code)

	for (( l=0;l<="$(( ${#uri[@]} - 1 ))";l++ ));
	do
            data=("${method[$l]}" "${uri[$l]}" "${hostname[$l]}" "${user_agent[$l]}" "${mime_type_rq[$l]}" "${mime_type_rp[$l]}" "${status_code[$l]}")
            preparing_log "${data[@]}"
	    print_log "$path_log"
	done

    elif [ "$service" == "ssl" ];
    then
	path_log="./$logs_dir/${logs[2]}"
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
	    your_mac=$(ifconfig $net_interface | grep 'ether' | awk '{print $2}')
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
	       your_ip=$(ifconfig $net_interface | grep -w 'inet6' | awk '{print $2}')
	       filter_files+=('./host_filter6.txt')
	       ip_filter="ipv6"
		
	   elif [ "$arg3" == "-4" ] ||
		[ "$arg3" == "--ipv4" ]
	   then
	       start_l7=$((start_l7+1))
	       your_ip=$(ifconfig $net_interface | grep -w 'inet' | awk '{print $2}')
	       filter_files+=('./host_filter4.txt')
	       ip_filter="ip"
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
	    aux_filter="(eth.src != ${your_mac} || ${ip_filter}.src != ${your_ip})"
	    
	elif [ "$arg4" == "--outgoing" ] ||
	     [ "$arg4" == "-out" ];
	then
	    start_l2=$((start_l2+1))
	    start_l7=$((start_l7+1))
	    logs=("${out_logs[@]}")
	    outgoing=0
	    aux_filter="(eth.src == ${your_mac} || ${ip_filter}.src == ${your_ip})"
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

	    default_general_filter="ether host ${your_mac} or host ${your_ip}"
	    default_service_filter=""
	    default_domain_filter=""
	    
	    trap killer SIGINT
	    clear

	    for (( i=0;i<="$(( ${#filter_files[@]} - 1 ))";i++ ));
	    do
		builder_filters "${filter_files[$i]}"
		if [[ "${filter_files[$i]}" =~ "./host_filter" ]];
		then
		    default_general_filter="${default_general_filter} ${init_keyword} ${parts[*]} ${final_keyword}"
		    
                elif [ "${filter_files[$i]}" == "./service_filter.txt" ];
		then
		    default_service_filter="${default_service_filter} ${init_keyword} ${parts[*]} ${final_keyword}"
		    
		elif [ "${filter_files[$i]}" == "./domain_filter.txt" ];
		then
		    default_domain_filter="${default_domain_filter} ${init_keyword} ${parts[*]} ${final_keyword}"
		fi
	    done

	    sniffer
	    echo -e "${green}\n [+] I'm Hunting....${default}"
	    
	    if [ "$layer7" -eq 0 ];
	    then
		sessions
		
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
