#!/bin/bash

source files.sh

declare -A event_counters
event_counters=(
    ["Connection"]=0
    ["DoS"]=0
)

tcp_ports=('21' '22' '25' '80' '443' '445' '1433' '3389')
udp_ports=('53' '68' '69')
opened_ports=()
captures=()
interfaces=$(ifconfig | awk '{print $1}' | grep ':' | tr -d ':')
local_ip=$(ifconfig enp4s0 | grep 'inet ' | awk '{print $2}')
n_elements=0
it=0
value=0
value2=0
folder=""

#flags
kill_filters=1
pcap_saved=1

#processes ID's
pid_sniffer=0
pid_filters=0

function killer() {

    kill $pid_sniffer
    kill_filters=0
    
    for file in $(ls -a .*.pcap);
    do
	rm $file
    done
    exit
}

function port_scanner() {
    
    for (( i=0;i<="${#tcp_ports[@]}";i++ ))
    do
        nc -zvn 127.0.0.1 "${tcp_ports[$i]}" 2> /dev/null
	if [ "$?" -eq 0 ];
	then
	    opened_ports+=("${tcp_ports[$i]}")
	fi
	
	if [ "$i" -eq "${#tcp_ports[@]}" ];
	then
	    for (( j=0;j<="${#udp_ports[@]}";j++ ));
	    do
		nc -zvnu 127.0.0.1 "${udp_ports[$j]}" 2> /dev/null
		if [ "$?" -eq 0 ];
		then
		    opened_ports+=("${udp_ports[$j]}")
		fi
	    done
        fi
    done
		
    echo "puertos escaneados"
    n_elements="${#opened_ports[@]}"
}

function sniffer() {
    
    tshark -w "${general_capture}" -i enp4s0 2> /dev/null &
    pid_sniffer=$!
}

function filters() {

    if [ "$n_elements" -gt 0 ];
    then
	for (( i=0;i<=$n_elements;i++ ));
	do
	    captures+=(".${opened_ports[$i]}.pcap")
            if [ "$i" -eq "$n_elements" ];
	    then
		while true;
		do  
		    for (( j=0;j<=$n_elements;j++ ));
		    do
			tshark -w "${captures[$j]}" -r "${general_capture}" -Y "tcp.port == ${opened_ports[$j]} && ip.addr == ${local_ip}" 2> /dev/null
			pid_filters=$!
			sleep 5 
		    done

		    if [ "$kill_filters" -eq 0 ];
		    then
			kill $pid_filters
			break
		    fi
		done
	    fi
	done
    fi
}

function pcap_saved() {
    
    if [ "$pcap_saved" -eq 0 ];
    then
	echo "[+] PCAP saved in $directory/$folder/$file"
    fi
}

function port_scan() {
    
    echo "pcap creado"
}

function DoS_obtain_pcap() {
    
    init_value=$(tshark -r '.80.pcap' 2> /dev/null | awk '{print $1}' | head -n 1)
    echo $init_value
    sleep 60
    final_value=$(tshark -r '.80.pcap' 2> /dev/null | awk '{print $1}' | tail -n 1)
    echo $final_value

    for subdirectory in "${subdirectories[@]}"
    do	
	if [ "$subdirectory" == "Denial_of_Service" ];
	then
	    while [ -f $directory/$subdirectory/$file ];
	    do
	        file="DoS-${id_pcap}.pcap"
		id_pcap=$((id_pcap+1))
	    done
	    tshark -w "$directory/$subdirectory/$file" -r '.80.pcap' -Y "frame.number >= ${init_value} && frame.number <= ${final_value}" 2> /dev/null
	    pcap_saved=0
	    folder=$subdirectory
	fi
    done
}

function clean_files() {

    echo "limpiando archivos"
    for file in $(ls -a .*.pcap)
    do
        truncate --size 0 $file
    done
    echo "listo"
    kill $pid_sniffer
    sniffer
}

function events_control() {

    for key in "${!event_counters[@]}";
    do
	value="${options[$key]}"
        event=$key

	if [[ "$denial" -eq 0 && "$event" == "DoS" ]];
	then
	    value=$((value+1))
	    value2=$((value2+value))
	fi

	if [[ "$connect" -eq 0 && "$event" == "Connection" ]];
	then
	    value=$((value+1))
	    value2=$((value2+value))
	fi
   done
}

function tcp_connections() {

    connection=False
    ip=$(tshark -r "${captures[$it]}" -Y "tcp.flags == 0x002" -T fields -e "ip.src" 2> /dev/null | head -n 1)
    srcport=$(tshark -r "${captures[$it]}" -Y "ip.src == ${ip} && tcp.flags == 0x002" -T fields -e "tcp.srcport" 2> /dev/null | head -n 1)
    condition1_scan=$(tshark -r "${captures[$it]}" -Y "ip.src == ${ip} && tcp.port == ${srcport}" -T fields -e "tcp.flags" 2> /dev/null | sort | uniq | tr -d '0x')
    array1=($condition1_scan)
    condition2_scan=$(tshark -r "${captures[$it]}" -Y "ip.src == ${local_ip} && tcp.port==${srcport}" -T fields -e "tcp.flags" 2> /dev/null | sort | uniq | tr -d '0x')
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
	        connection=True
	    fi
	done
    done
		    
    if [ "$connection" == "True" ];
    then
	connect=0
	events_control
        if [[ "$value2" -gt 0 && "$value2" -lt 2 ]];
	then
	    echo "[ALERT] ! ==> The ip [${ip}] established a connection to the port ${port}."
	fi
    fi
    unset -v array1
    unset -v array2
}

function tcp_DoS() {
    
     condition1_DoS=$(tshark -r "${captures[$it]}" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.srcport" 2> /dev/null | sort | uniq | wc -l)
     condition2_DoS=$(tshark -r "${captures[$it]}" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.flags" 2> /dev/null | wc -l)
		
     if [[ "$condition1_DoS" -gt 100 || "$condition2_DoS" -gt 100 ]];
     then
	 denial=0
	 events_control
	 if [[ "$value2" -gt 0 && "$value2" -lt 2 ]];
	 then
	    echo "[ALERT] ! ==> Possible TCP DoS attack detected."
	    DoS_obtain_pcap
	    pcap_saved
	 fi
     fi
}

function main() {

    port_scanner
    sniffer
    trap killer SIGINT
    filters &

    for (( i=0;i<=$n_elements;i++ ));
    do
	captures+=(".${opened_ports[$i]}.pcap")
    done
    
    while true;
    do
	for (( i=0;i<=5;i++ ));
	do
	    sleep 5
            for (( j=0;j<=$n_elements;j++ ));
	    do
		port="${opened_ports[$j]}"
		it=$j

		#Attacks that apply to all tcp/udp ports
		if [[ "$port" != '53' && "$port" != '68' && "$port" != '69' ]];
		then
		    tcp_connections
		    tcp_DoS	    
	        fi
	    done
	    if [ "$i" -eq 5 ];
	    then
	        clean_files
		sleep 10
		value2=0
      	    fi
	done
    done
}

echo "[+] sniffing"
main

