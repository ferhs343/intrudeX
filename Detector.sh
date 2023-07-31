#!/bin/bash

# intrudeX
# --------
# Herramienta enfocada a la detección de intrusos en tu host local.
#    - Detección de ataques a nivel de capa de aplicación, así como a nivel de capa 2
#    - Detección de tecnicas de reconocimiento
#    - Así mismo, intrudeX cuenta con utilidades para la ejecución de Threat Intellingece
# Luis Herrera, Abril 2023

source Files.sh
source Alerts.sh
source Colors.sh

tcp_ports=('21' '22' '25' '80' '443' '445' '1433' '3389')
udp_ports=('53' '68' '69')
other_protocols=('arp' 'stp' 'dtp' 'cdp' 'lldp' 'icmp')
opened_ports=()
traffic_captures=()
interfaces_list=$(ifconfig | awk '{print $1}' | grep ':' | tr -d ':')
interfaces=()
subdirectory_to_save=""

#processes ID's
pid_separate=""
pid_sniffer=""

#flags
kill_separator=1
pcap_saved=1
layer7=1
layer2=1
handshake=False
tcp_denial=False
banner_grabbing=False

function show_help() {

    echo -e "${yellow}\n intrudeX V 1.0.0 - By: Luis Herrera${green}"
    echo -e "\n Usage: ./intrudex.sh [INTERFACE] [LAYER] [IP_FORMAT]"
    echo -e "\n\t -h, --help: Show this panel."
    echo -e "\n\t -l, --list-interfaces: Show available interfaces in your system."
    echo -e "\n\t -i, --interface: Establish a listening interface."
    echo -e "\n\t ${yellow}[LAYER OPTIONS] ${green}"
    echo -e "\n\t -7, --layer7: Sniff in layer 7."
    echo -e "\n\t -3, --layer3: Sniff in layer 3."
    echo -e "\n\t -2, --layer2: Sniff in layer 2."
    echo -e "\n\t ${yellow}[IP OPTIONS] ${green}"
    echo -e "\n\t -6, --ipv6: Use IPv6"
    echo -e "\n\t -4, --ipv4: Use IPv4.\n${default}"
}

function killer() {

    kill $pid_sniffer
    kill_separator=0
    
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

function pcap_saved() {

    if [ "$pcap_saved" -eq 0 ];
    then
	echo -e "${yellow} Pcap file saved in ==> $directory/$subdirectory_to_save/$file ${default}"
    fi
}

function sniffer() {

    tshark -w "${general_capture}" -i $net_interface 2> /dev/null &
    pid_sniffer=$!
    #principal sniffer process ID
}

function clean_captures() {

    truncate --size 0 $general_capture
    truncate --size 0 "${traffic_captures[$index]}"    
    kill $pid_sniffer
    sniffer
}

function separate() {

    while true;
    do
	count=0
        for (( i=0;i<="$(( ${#traffic_captures[@]} - 1 ))";i++ ));
	do
	    if [ "$layer7" -eq 0 ];
	    then
		impacted_port="${opened_ports[$i]}"
		if [[ "$impacted_port" != '53' && "$impacted_port" != '68' && "$impacted_port" != '69' ]];
		then
		    filter="tcp.port == ${backup_array[$i]} && ip.addr == ${your_ip}"
		else
		    filter="udp.port == ${backup_array[$i]} && ip.addr == ${your_ip}"
		fi

	    elif [ "$layer2" -eq 0 ];
	    then
		filter="${backup_array[$i]}"
	    fi
	    
	    packets_number=$(tshark -r "${general_capture}" -Y "${filter}" 2> /dev/null | wc -l)
	    if [ "$(( packets_number ))" -gt 0 ];
	    then
		tshark -w "${traffic_captures[$i]}" -r "${general_capture}" -Y "${filter}" 2> /dev/null
		pid_separate=$!
	    else
		count=$((count+1))
	        if [ "$count" -eq "$(( ${#traffic_captures[@]} - 1 ))" ];
	        then
		    sleep 5
		fi
	    fi
	done
	
	if [ "$kill_separator" -eq 0 ];
	then
	    kill $pid_separate
	    break
        fi
    done
}

function get_subdirectory() {

    id_pcap=0
    file="capture-${id_pcap}.pcap"
    
    for subdirectory in "${subdirectories[@]}"
    do	
	if [[ "$subdirectory" == "Denial_of_Service"  && "$tcp_denial" == "True" ]];
	then
	    subdirectory_to_save=$subdirectory
	    tcp_denial=False
	fi

	if [[ "$subdirectory" == "Brute_Force" && "$handshake" == "True" ]];
	then
	    subdirectory_to_save=$subdirectory
	    handshake=False
	fi
    done

    while [ -f $directory/$subdirectory_to_save/$file ];
    do
	id_pcap=$((id_pcap+1))
        file="capture-${id_pcap}.pcap"
    done
}

function obtain_pcap() {

    init_value=$(tshark -r "${traffic_captures[$index]}" 2> /dev/null | awk '{print $1}' | head -n 1)
    final_value=$(tshark -r "${traffic_captures[$index]}" 2> /dev/null | awk '{print $1}' | tail -n 1)
    get_subdirectory
    tshark -w "$directory/$subdirectory_to_save/$file" -r "${traffic_captures[$index]}" -Y "frame.number >= ${init_value} && frame.number <= ${final_value}" 2> /dev/null
    pcap_saved=0
    pcap_saved
}

function show_alert() {

    time=$(date +%H:%M:%S)
    
    if [ "$handshake" == "True" ];
    then
        echo -e "\n ${green}[$time]\n${red} ${tcp_connection_alert} ${yellow}[${ip}:${impacted_port}]${default}"
	
    elif [ "$tcp_denial" == "True" ];
    then
	echo -e "\n ${green}[$time]\n${red} ${tcp_DoS_alert}${default}"

    elif [ "$ping" == "True" ];
    then
	echo -e "\n${green} [$time]\n${red} ${ping_alert}${default}"
    fi

    count_alert=$((count_alert+1))
}

function tcp_connection_alert() {

    ip=$(tshark -r "${traffic_captures[$index]}" -Y "tcp.flags == 0x002" -T fields -e "ip.src" 2> /dev/null | head -n 1)
    srcport=$(tshark -r "${traffic_captures[$index]}" -Y "ip.src == ${ip} && tcp.flags == 0x002" -T fields -e "tcp.srcport" 2> /dev/null | head -n 1)
    condition1_scan=$(tshark -r "${traffic_captures[$index]}" -Y "ip.src == ${ip} && tcp.port == ${srcport}" -T fields -e "tcp.flags" 2> /dev/null | sort | uniq | tr -d '0x')
    array1=($condition1_scan)
    condition2_scan=$(tshark -r "${traffic_captures[$index]}" -Y "ip.src == ${your_ip} && tcp.port==${srcport}" -T fields -e "tcp.flags" 2> /dev/null | sort | uniq | tr -d '0x')
    array2=($condition2_scan)
		    
    for (( k=0;k<="${#array1[@]}";k++ ));
    do
        for (( l=0;l<="${#array2[@]}";l++ ));
        do
	    if [ "${array1[$k]}" == "2" ];
	    then
	        syn=True
	    fi

	    if [[ "${array2[$l]}" == "12" && "$syn" == "True" ]];
	    then
	        synack=True
	    fi

	    if [[ "${array1[$k]}" == "1" && "$synack" == "True" ]];
	    then
	        handshake=True
	    fi
	done
    done

    if [ "$handshake" == "True" ];
    then
	show_alert
	obtain_pcap
    fi
    
    unset array1[*]
    unset array2[*]
}

function tcp_dos_alert() {

    condition1_DoS=$(tshark -r "${traffic_captures[$index]}" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.srcport" 2> /dev/null | sort | uniq | wc -l)
    condition2_DoS=$(tshark -r "${traffic_captures[$index]}" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.flags" 2> /dev/null | wc -l)
		
    if [[ "$condition1_DoS" -gt 100 || "$condition2_DoS" -gt 100 ]];
    then
	tcp_denial=True
	show_alert
	obtain_pcap
    fi
}

function ping_alert() {

    count_ping=0
    condition1_ping=$(tshark -r "${traffic_captures[$index]}" -Y "icmp.type == 8" -T fields -e "icmp.seq" 2> /dev/null)
    array1=($condition1_ping)
    condition2_ping=$(tshark -r "${traffic_captures[$index]}" -Y "icmp.type == 0" -T fields -e "icmp.seq" 2> /dev/null)
    array2=($condition2_ping)

    for (( i=0;i<="$(( ${#array1[@]} - 1 ))";i++ ));
    do
	for (( j=0;j<="$(( ${#array2[@]} - 1 ))";j++ ));
	do
	    if [ "${array1[$i]}" == "${array2[$j]}" ];
	    then
		count_ping=$((count_ping+1))
	    fi
	done
    done

    if [ "$count_ping" -gt 0 ];
    then
	ping=True
	show_alert
    fi
    
    unset array1[*]
    unset array2[*]
}




function l7_start_attack_detection() {

    if [[ "$impacted_port" != '53' && "$impacted_port" != '68' && "$impacted_port" != '69' ]];
    then
        tcp_dos_alert
	tcp_connection_alert
    fi 
}

function l2_start_attack_detection() {

    if [ "$protocol" == 'icmp' ];
    then
	ping_alert
    fi
}

function analyzer() {
    
    while true;
    do
	for (( i=0;i<="$(( ${#backup_array[@]} - 1 ))";i++ ));
        do
	    validate=$(tshark -r "${traffic_captures[$i]}" 2> /dev/null | wc -l)
	    index=$i
	    
	    if [[ "$validate" -gt 0 && "$layer7" -eq 0 ]];
	    then
	        impacted_port="${backup_array[$i]}"
                l7_start_attack_detection
                clean_captures
		    
	    elif [[ "$validate" -gt 0 && "$layer2" -eq 0 ]];
	    then
	        protocol="${backup_array[$i]}"
	        l2_start_attack_detection
	    fi
	done

	sleep 5
    done
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
    echo -e "${green}\n Loading....${default}"
    port_scanner
    sleep 5

    if [[ "$layer7" -eq 0 && "$layer2" -eq 1 ]];
    then
	if [ "${#opened_ports[@]}" -lt 1 ];
	then
	    layer7=1
	    layer2=0
	else
	    your_ip=$(ifconfig $net_interface | grep 'inet ' | awk '{print $2}')
	fi
    fi

    if [ "$layer7" -eq 0 ];
    then
	generate_files "${opened_ports[@]}"
	backup_array=("${opened_ports[@]}")
	
    elif [ "$layer2" -eq 0 ];
    then
	generate_files "${other_protocols[@]}"
	backup_array=("${other_protocols[@]}")
    fi

    trap killer SIGINT
    sniffer
    separate &
    clear
    echo -e "${green}\n [+] Sniffing in ${net_interface} interface....${default}"
    analyzer
}

arg=$1
arg2=$3
arg3=$4
if [ "$(id -u)" == "0" ];
then
    check=0
    if [ "$arg" == "--help" ] || [ "$arg" == "-h" ]
    then
	show_help
        exit

    elif  [ "$arg" == "--list-interfaces" ] || [ "$arg" == "-l" ]
    then
        interfaces=($interfaces_list)
	echo -e "${yellow}\n Available interfaces:\n"
	for (( i=0;i<="$(( ${#interfaces[@]} - 1 ))";i++ ));
	do
	    echo -e "${green} [+] ${interfaces[$i]}${default}\n"
	done

    elif [ "$arg" == "--interface" ] || [ "$arg" == "-i" ]
    then
	start=1
        net_interface=$2
        interfaces=($interfaces_list)
	for (( i=0;i<="$(( ${#interfaces[@]} - 1 ))";i++ ));
	do
	    if [ "$net_interface" == "${interfaces[$i]}" ];
	    then
		check=$((check+1))
		break
	    fi
	done

	if [ "$arg2" == "--layer7" ] || [ "$arg2" == "-t" ]
        then
	    layer7=0
	    check=$((check+1))

	elif [ "$arg2" == "--layer2" ] || [ "$arg2" == "-nt" ]
	then
	    layer2=0
	    check=$((check+1))
	fi
	
	if [ "$start" -eq 0 ];
	then
	    main
	else
	    echo -e "${red}\n ERROR, The especified interface is not correct, try again.\n${default}"
	    sleep 2
	fi
    else
	show_help
	exit
    fi
else
    echo -e "${red} ERROR, to run intrudeX you must be root user.${default}"
    sleep 3
fi




