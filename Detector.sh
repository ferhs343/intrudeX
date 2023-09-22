#!/bin/bash

# -------------------------------------------------------------------------------------------------------------------------------
# | intrudeX                                                                                                                    |
# |                                                                                                                             |
# | Herramienta enfocada a la seguridad de puntos finales, detectando patrones maliciosos mediante el tráfico de red entrante   |
# | y saliente, en base a las tácticas y técnicas del framwork MITRE ATT&CK.                                                    |
# |                                                                                                                             |
# | Autor: Luis Herrera ~ @ferhs343                                                                                             |
# | Contacto: fer.hs343@gmail.com                                                                                               |
# -------------------------------------------------------------------------------------------------------------------------------

source Files.sh
source Alerts.sh
source Colors.sh

#Tcp/Udp ports 
tcp_ports=('21' '22' '23' '25' '80' '139' '443' '445' '1433' '3306' '3389' '5432')
udp_ports=('53' '68' '69' '546')
opened_ports=()

#Layer 2 protocols
l2_protocols=('arp' 'stp' 'dtp' 'cdp' 'lldp')
auxiliar_protocols=('arp' 'icmp' 'icmpv6')

to_analyze=()
traffic_captures=()
interfaces_list=$(ifconfig | awk '{print $1}' | grep ':' | tr -d ':')
interfaces=()
subdirectory_to_save=""

#processes ID's
pid_sniffer=""

#flags
layer2=1
layer7=1
ipv4=1
ipv6=1
incoming=1
outgoing=1

#terminal arguments
arg=$1
arg2=$3
arg3=$4
arg4=$5

function show_help() {

    echo -e "${yellow}\n intrudeX V 1.0.0 - By: Luis Herrera${green}"
    echo -e "\n Usage: ./intrudex.sh [INTERFACE] [LAYER] [IP_FORMAT] [ANALYZE_MODE]"
    echo -e "\n\t -h, --help: Show this panel."
    echo -e "\n\t -l, --list-interfaces: Show available interfaces in your system."
    echo -e "\n\t -i, --interface: Establish a listening interface."
    echo -e "\n\t ${yellow}[LAYERS] ${green}"
    echo -e "\n\t -l7, --layer7: Sniff in layer 7."
    echo -e "\n\t -l2, --layer2: Sniff in layer 2."
    echo -e "\n\t ${yellow}[IP FORMATS] ${green}"
    echo -e "\n\t -6, --ipv6: Use IPv6"
    echo -e "\n\t -4, --ipv4: Use IPv4."
    echo -e "\n\t ${yellow}[ANALYZE MODES] ${green}"
    echo -e "\n\t -in, --inbound: Analyze incoming traffic."
    echo -e "\n\t -out, --outbound: Analyze outgoing traffic.\n${default}"
}

function killer() {

    kill $pid_sniffer
    
    for file in $(ls -a .*.pcap);
    do
	rm $file
    done
    exit
}

function port_scanner() {
    
    for (( i=0;i<="$(( ${#tcp_ports[@]} - 1 ))";i++ ));
    do
        nc -zvn 127.0.0.1 "${tcp_ports[$i]}" 2> /dev/null
	if [ "$?" -eq 0 ];
	then
	    opened_ports+=("${tcp_ports[$i]}")
	fi
	
	if [ "$i" -eq "$(( ${#tcp_ports[@]} -1 ))" ];
	then
	    for (( j=0;j<="$(( ${#udp_ports[@]} -1 ))";j++ ));
	    do
		nc -zvnu 127.0.0.1 "${udp_ports[$j]}" 2> /dev/null
		if [ "$?" -eq 0 ];
		then
		    opened_ports+=("${udp_ports[$j]}")
		fi
	    done
        fi
    done
}

function demux() {

    while true;
    do
	control=0
	for (( i=0;i<="$(( ${#traffic_captures[@]} - 1 ))";i++ ));
	do
	    if [ "$layer7" -eq 0 ];
	    then
		if [ "$i" -gt "$((n_elements - 1))" ];
		then
	            port="${to_analyze[$i]}"
		    
		    if [[ "$port" != '53' &&
			  "$port" != '68' &&
		          "$port" != '69' ]];
		    then
			filter="tcp.port == ${to_analyze[$i]}"
		    else
			filter="udp.port == ${to_analyze[$i]}"
		    fi
		fi

		if [ "$i" -le "$((n_elements - 1))" ];
		then
		    protocol="${to_analyze[$i]}"
		    
		    if [ "$protocol" == 'arp' ];
		    then
			filter="(arp.opcode == 1 && arp.dst.proto_ipv4 == ${your_ip}) || (arp.opcode == 2 && eth.src == ${your_mac})"
			
		    elif [ "$protocol" == 'icmpv6' ];
		    then
			filter="icmpv6.nd.ns.target_address == ${your_ip} || icmpv6.nd.na.target_address == ${your_ip}"

		    elif [ "$protocol" == 'icmp' ];
		    then
			filter="${protocol} && eth.addr == ${your_mac}"
		    fi
		fi
	    fi

	    if [ "$layer2" -eq 0 ];
	    then
		filter="${to_analyze[$i]}"
	    fi

	    n_packets=$(tshark -r "${general_capture}" -Y "${filter}" 2> /dev/null | wc -l)
	    if [ "$(( n_packets ))" -gt 0 ];
	    then
		tshark -w "${traffic_captures[$i]}" -r "${general_capture}" -Y "${filter}" 2> /dev/null
	    else
		control=$((control+1))
	        if [ "$control" -eq "$(( ${#traffic_captures[@]} - 1 ))" ];
	        then
		    sleep 5
		fi
	    fi
	done
    done
}

function sniffer() {

    if [ "$layer7" -eq 0 ];
    then
	tshark -w "${general_capture}" -i $net_interface -f "host ${your_ip}" 2> /dev/null &
    elif [ "$layer2" -eq 0 ];
    then
	tshark -w "${general_capture}" -i $net_interface -f "not tcp and not udp" 2> /dev/null &
    fi
    
    pid_sniffer=$!
    #principal sniffer process ID
    demux &   
}

function validator() {

    start=0
    control=0
    for (( i=0;i<="$(( ${#traffic_captures[@]} - 1 ))";i++ ));
    do
        index=$i
        validate=$(tshark -r "${traffic_captures[$i]}" 2> /dev/null | wc -l)
	if [ "$(( validate ))" -gt 0 ];
	then
	    start=$((start+1))
	else
	    control=$((control+1))
	    if [ "$control" -eq "$(( ${#traffic_captures[@]} - 1 ))" ];
	    then
	        sleep 5
	    fi
	fi
	    
        if [[ "$(( start ))" -gt 0 &&
              "$layer7" -eq 0 ]];
        then
            if [ "$i" -gt "$(( n_elements - 1 ))" ];
	    then
		impacted_port="${to_analyze[$i]}"
		    
	    elif [ "$i" -le "$(( n_elements - 1 ))" ];
	    then
	        protocol="${to_analyze[$i]}"
            fi
	    #Start analysis based on MITRE ATT&CK 
	    start_TA0043
	    #start_TA0042
	    #start_TA0001
	    #start_TA0002
	fi

	if [[ "$(( start ))" -gt 0 &&
              "$layer2" -eq 0 ]];
	then
	    protocol="${to_analyze[$i]}"
	    start_hunting_l2
	fi
    done
    validator
}

function check_origin() {

    origin=$(tshark -r "${traffic_captures[$index]}" -T fields -e "ip.src" 2> /dev/null | head -n 1)
    keep_going=1
    if [ "$incoming" -eq 0 ];
    then
	if [ "$origin" != "${your_ip}" ];
	then
	    keep_going=0
	fi
	
    elif [ "$outgoing" -eq 0 ];
    then
	if [ "$origin" == "${your_ip}" ];
	then
	    keep_going=0
	fi
    fi
}

function start_TA0043() {

    check_origin
    if [ "$keep_going" -eq 0 ];
    then

	# ============ T00043 ============
	
	srcport=$(tshark -r "${traffic_captures[$index]}" -Y "tcp.flags == 0x002" -T fields -e "tcp.srcport" 2> /dev/null | head -n 1)
	condition1_scan=$(tshark -r "${traffic_captures[$index]}" -Y "tcp.port == ${srcport}" -T fields -e "tcp.flags" 2> /dev/null | sort | uniq | tr -d '0x')
	array1=($condition1_scan)
	condition2_scan=$(tshark -r "${traffic_captures[$index]}" -Y "tcp.port==${srcport}" -T fields -e "tcp.flags" 2> /dev/null | sort | uniq | tr -d '0x')
	array2=($condition2_scan)
		    
	for (( k=0;k<="${#array1[@]}";k++ ));
	do
            for (( l=0;l<="${#array2[@]}";l++ ));
            do
		if [ "${array1[$k]}" == "2" ];
		then
	            syn=True
		fi

		if [[ "${array2[$l]}" == "12" &&
		      "$syn" == "True" ]];
		then
	            synack=True
		fi

		if [[ "${array1[$k]}" == "1" &&
		      "$synack" == "True" ]];
		then
	            handshake=True
		    echo "ALERT"
		fi
	    done
	done
    fi
}

function start_hunting_l2() {
    continue
}

function generate_files() {
    
    local_array=("$@")

    for (( i=0;i<="$(( ${#local_array[@]} - 1 ))";i++ ));
    do
	element="${local_array[$i]}"
	file_element=".${element}.pcap"
        traffic_captures+=($file_element)
        touch "${traffic_captures[$i]}"
    done
}

function main() {

    clear
    echo -e "${green}\n [+] Loading, wait a moment....${default}"
    sleep 5
    
    if [ "$layer7" -eq 0 ];
    then
	if [ "$ipv6" -eq 0 ];
	then
	    your_ip=$(ifconfig $net_interface | grep 'inet6' | awk '{print $2}')
	    
	elif [ "$ipv4" -eq 0 ];
        then
       	    your_ip=$(ifconfig $net_interface | grep 'inet ' | awk '{print $2}')
	fi
	
	if [ "$incoming" -eq 0 ];
	then
	    port_scanner
	    sleep 5
	    if [ "${#opened_ports[@]}" -lt 1 ];
	    then
		no_ports="[+] Warning, you dont have opened ports, analyzing outgoing traffic.....\n"
		incoming=1
		outgoing=0
	    fi
	fi

	if [ "$incoming" -eq 0 ];
	then 
	    for (( i=0;i<="$(( ${#auxiliar_protocols[@]} - 1 ))";i++ ));
	    do
		if [ "$ipv6" -eq 0 ];
		then
	            if [ "${auxiliar_protocols[$i]}" == 'icmpv6' ];
                    then
              		to_analyze+=("${auxiliar_protocols[$i]}")
		    fi

		elif [ "$ipv4" -eq 0 ];
		then
		    if [[ "${auxiliar_protocols[$i]}" == 'arp' ||
		          "${auxiliar_protocols[$i]}" == 'icmp' ]];
	            then
			to_analyze+=("${auxiliar_protocols[$i]}")
		    fi
		fi
	    done
	    n_elements="${#to_analyze[@]}"
	    to_analyze+=("${opened_ports[@]}")
	fi

	if [ "$outgoing" -eq 0 ];
	then
	    for (( i=0;i<="$(( ${#auxiliar_protocols[@]} - 1 ))";i++ ));
	    do
	        if [ "$ipv6" -eq 0 ];
	       	then
	            if [ "${auxiliar_protocols[$i]}" == 'icmpv6' ];
		    then
		        to_analyze+=("${auxiliar_protocols[$i]}")
		    fi

		elif [ "$ipv4" -eq 0 ];
		then
		    if [[ "${auxiliar_protocols[$i]}" == 'arp' ||
			  "${auxiliar_protocols[$i]}" == 'icmp' ]];
		    then
		        to_analyze+=("${auxiliar_protocols[$i]}")
		    fi
		fi

		n_elements="${#to_analyze[@]}"

		if [ "$i" -eq "$(( ${#auxiliar_protocols[@]} - 1 ))" ];
		then
		    for (( j=0;j<="$(( ${#tcp_ports[@]} - 1 ))";j++ ));
		    do
			to_analyze+=("${tcp_ports[$j]}")
			if [ "$j" -eq "$(( ${#tcp_ports[@]} - 1 ))" ];
			then
			    for (( k=0;k<="$(( ${#udp_ports[@]} - 1))";k++ ));
			    do
				to_analyze+=("${udp_ports[$k]}")
			    done
			fi
		    done
		fi
	    done
	fi
    fi
    
    if [ "$layer2" -eq 0 ];
    then
	for (( i=0;i<="$(( ${#auxiliar_protocols[@]} - 1 ))";i++ ));
        do
	    if [ "${auxiliar_protocols[$i]}" == 'icmpv6' ];
	    then
	        to_analyze+=("${auxiliar_protocols[$i]}")
            fi
	done
	to_analyze+=("${l2_protocols[@]}")
    fi
    
    your_mac=$(ifconfig $net_interface | grep 'eth' | awk '{print $2}')
    generate_files "${to_analyze[@]}"

    trap killer SIGINT
    clear
    sniffer
    echo -e "${green}\n [+] Detecting threats....${default}"
    echo -e "${yellow}\n ${no_ports}${default}"
    validator
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
	    main
	else
	    echo -e "${red}\n ERROR, any of the specified arguments are not valid.${default}"
	    sleep 2
	    show_help
	fi
    else
        show_help
        exit
    fi
else
    echo -e "${red} ERROR, to run intrudeX you must be root user.${default}"
    sleep 5
fi


