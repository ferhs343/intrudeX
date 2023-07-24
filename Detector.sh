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
layer2_3_protocols=('arp' 'stp' 'dtp' 'cdp' 'lldp' 'icmp')
opened_ports=()
traffic_captures=()
traffic_captures_l2_3=()
interfaces_list=$(ifconfig | awk '{print $1}' | grep ':' | tr -d ':')
interfaces=()
subdirectory_to_save=""

#processes ID's
pid_separate=""
pid_sniffer=""

#flags
kill_separator=1
pcap_saved=1
analyze_l7=1
tcp_connection=False
tcp_denial=False
banner_grabbing=False

function show_help() {

    echo -e "${yellow}\n intrudeX V 1.0.0 - By: Luis Herrera${green}"
    echo -e "\n ¿How to use?"
    echo -e "\n\t -i, --interface:Establish a listening interface."
    echo -e "\n\t -l, --list-interfaces:Show available interfaces in your system."
    echo -e "\n\t -h, --help:Show this panel.\n${default}"
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
	if [ "$analyze_l7" -eq 0 ];
	then
	    for (( i=0;i<="$(( ${#traffic_captures[@]} - 1 ))";i++ ));
	    do
		packets_number=$(tshark -r "${general_capture}" -Y "tcp.port == ${opened_ports[$i]} && ip.addr == ${your_ip}" 2> /dev/null | wc -l)
		if [ "$((packets_number))" -gt 0 ];
		then
		    tshark -w "${traffic_captures[$i]}" -r "${general_capture}" -Y "tcp.port == ${opened_ports[$i]} && ip.addr == ${your_ip}" 2> /dev/null
		    pid_separate=$!
		fi
	    done
	fi

	#optimizar bien esta parte, agregando los elementos de capa2 al normal e meter este bloque arriba, asi como modificar la agregacion de los archivos al arreglo 
	for (( i=0;i<="$(( ${#traffic_captures_l2_3[@]} - 1 ))";i++ ));
	do
	    packets_number=$(tshark -r "${general_capture}" -Y "${layer2_3_protocols[$i]}" 2> /dev/null | wc -l)
	    if [ "$((packets_number))" -gt 0 ];
	    then
	        tshark -w "${traffic_captures_l2_3[$i]}" -r "${general_capture}" -Y "${layer2_3_protocols[$i]}" 2> /dev/null
	        pid_separate=$!
	    fi
	done
	
	if [ "$kill_separator" -eq 0 ];
	then
	    kill $pid_separate
	    break
        fi
    done
}

function pcap_saved() {

    if [ "$pcap_saved" -eq 0 ];
    then
	echo -e "${yellow} Pcap file saved in ==> $directory/$subdirectory_to_save/$file ${default}"
    fi
}

function show_alert() {

    time=$(date +%H:%M:%S)
    if [ "$handshake" == "True" ];
    then
        echo -e "\n ${green}[$time]\n${red} ${tcp_connection_alert}\n ${yellow}${ip}:${impacted_port}${default}"
	
    elif [ "$tcp_denial" == "True" ];
    then
	echo -e "\n ${green}[$time]\n${red} ${tcp_DoS_alert}${default}"
    fi
}

function get_subdirectory() {

    id_pcap=0

    for subdirectory in "${subdirectories[@]}"
    do	
	if [[ "$subdirectory" == "Denial_of_Service"  && "$tcp_denial" == "True" ]];
	then
	    subdirectory_to_save=$subdirectory
     	    tcp_denial=False
	fi
    done

    while [ -f $directory/$subdirectory_to_save/$file ];
    do
        id_pcap=$((id_pcap+1))
    	file="capture-${id_pcap}.pcap"
    done
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
        dos_obtain_pcap
    fi
    unset array1[*]
    unset array2[*]
}

function dos_obtain_pcap() {

    init_value=$(tshark -r "${traffic_captures[$index]}" 2> /dev/null | awk '{print $1}' | head -n 1)
    if [ "$tcp_denial" == "True" ];
    then
    	sleep 60
    fi
    final_value=$(tshark -r "${traffic_captures[$index]}" 2> /dev/null | awk '{print $1}' | tail -n 1)
    get_subdirectory
    tshark -w "$directory/$subdirectory_to_save/$file" -r "${traffic_captures[$index]}" -Y "frame.number >= ${init_value} && frame.number <= ${final_value}" 2> /dev/null
    pcap_saved=0
    pcap_saved
}

function tcp_dos_alert() {

    condition1_DoS=$(tshark -r "${traffic_captures[$index]}" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.srcport" 2> /dev/null | sort | uniq | wc -l)
    condition2_DoS=$(tshark -r "${traffic_captures[$index]}" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.flags" 2> /dev/null | wc -l)
		
    if [[ "$condition1_DoS" -gt 100 || "$condition2_DoS" -gt 100 ]];
    then
	tcp_denial=True
	show_alert
	dos_obtain_pcap
    fi
}

function start_attack_detection() {

    if [[ "$impacted_port" != '53' && "$impacted_port" != '68' && "$impacted_port" != '69' ]];
    then
	tcp_connection_alert
        tcp_dos_alert
    fi 
}

function analyzer() {
    
    while true;
    do
	if [ "$analyze_l7" -eq 0 ];
	then
            for (( i=0;i<="$(( ${#opened_ports[@]} - 1 ))";i++ ));
	    do
		validate=$(tshark -r "${traffic_captures[$i]}" 2> /dev/null | wc -l)
		if [ "$validate" -gt 0 ];
		then
		    index=$i
	            impacted_port="${opened_ports[$i]}"
	            start_attack_detection
		    clean_captures
		fi
	    done
        fi

	sleep 5
    done
}

function main() {

    clear
    echo -e "${green}\n Loading....${default}"
    port_scanner
    sleep 5

    if [ "${#opened_ports[@]}" -gt 0 ];
    then
	analyze_l7=0
	your_ip=$(ifconfig $net_interface | grep 'inet ' | awk '{print $2}')
	
	for (( i=0;i<="$(( ${#opened_ports[@]} - 1 ))";i++ ));
	do
	    port="${opened_ports[$i]}"
	    file_port=".${port}.pcap"
            traffic_captures+=($file_port)
	    touch "${traffic_captures[$i]}"
	done	
    else
	echo -e "${yellow}\n [+] Warning! You dont have open ports to start attack detection, only detection of layer 2 attacks will be performed.${default}\n"
	sleep 5
    fi

    for (( i=0;i<="$(( ${#layer2_3_protocols[@]} - 1 ))";i++ ));
    do
	file_l2_3=".${layer2_3_protocols[$i]}.pcap"
	traffic_captures_l2_3+=($file_l2_3)
	touch "${traffic_captures_l2_3[$i]}"
    done

    trap killer SIGINT
    sniffer
    separate &
    clear
    echo -e "${green}\n [+] Sniffing in ${net_interface} interface....${default}"
    analyzer
}

arg=$1
if [ "$(id -u)" == "0" ];
then
    if [ "$arg" == "--help" ] || [ "$arg" == "-h" ]
    then
	show_help
	exit

    elif [ "$arg" == "--interface" ] || [ "$arg" == "-i" ]
    then
	start=1
        net_interface=$2
        interfaces=($interfaces_list)
	for (( i=0;i<="$(( ${#interfaces[@]} - 1 ))";i++ ));
	do
	    if [ "$net_interface" == "${interfaces[$i]}" ];
	    then
		start=0
		break
	    fi
	done

	if [ "$start" -eq 0 ];
	then
	    main
	else
	    echo -e "${red}\n ERROR, The especified interface is not correct, try again.\n${default}"
	    sleep 2
	fi
	
    elif  [ "$arg" == "--list-interfaces" ] || [ "$arg" == "-l" ]
    then
        interfaces=($interfaces_list)
	echo -e "${yellow}\n Available interfaces:\n"
	for (( i=0;i<="$(( ${#interfaces[@]} - 1 ))";i++ ));
	do
	    echo -e "${green} [+] ${interfaces[$i]}${default}\n"
	done
    else
	show_help
	exit
    fi
else
    echo -e "${red} ERROR, to run intrudeX you must be root user.${default}"
    sleep 3
fi



