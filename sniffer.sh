#!/bin/bash

source files.sh

predefined_ports=('21' '22' '25' '80' '443' '445' '1433')
ports=()
captures=()
interfaces=$(ifconfig | awk '{print $1}' | grep ':' | tr -d ':')
local_ip=$(ifconfig ens33 | grep 'inet ' | awk '{print $2}')
n_elements=0

#flags
cleanFiles=1
kill_filters=1

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
    
    for (( i=0;i<=1024;i++ ))
    do
        nc -zvn 127.0.0.1 $i 2> /dev/null
	if [ "$?" -eq 0 ];
	then
	    for (( j=0;j<="${#predefined_ports[@]}";j++ ))
	    do
		if [ "$i" == "${predefined_ports[$j]}" ];
		then
		    ports+=("$i")
		fi
	    done
	fi
    done

    echo "puertos escaneados"
    n_elements="${#ports[@]}"
}

function sniffer() {

    tshark -w "${general_capture}" -i ens33 2> /dev/null &
    pid_sniffer=$!
}

function filters() {

    if [ "$n_elements" -gt 0 ];
    then
	for (( i=0;i<=$n_elements;i++ ));
	do
	    captures+=(".${ports[$i]}.pcap")
            if [ "$i" -eq "$n_elements" ];
	    then
		while true;
		do  
		    for (( j=0;j<=$n_elements;j++ ));
		    do
			tshark -w "${captures[$j]}" -r "${general_capture}" -Y "tcp.port == ${ports[$j]} && ip.addr == ${local_ip}" 2> /dev/null
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

function port_scan() {
    
    echo "pcap creado"
}

function denial_of_service() {
    
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
		id=$((id+1))
	        file="DoS-${id}.pcap"
	    done
	    tshark -w "$directory/$subdirectory/$file" -r '.80.pcap' -Y "frame.number >= ${init_value} && frame.number <= ${final_value}" 2> /dev/null
	    echo "pcap creado"
	fi
    done
    cleanFiles=0
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
    cleanFiles=1
}

function detector() {

    port_scanner
    sniffer
    trap killer SIGINT
    filters &

    for (( i=0;i<=$n_elements;i++ ));
    do
	captures+=(".${ports[$i]}.pcap")
    done
    
    while true;
    do
	for (( i=0;i<=10;i++));
	do
            for (( j=0;j<=$n_elements;j++ ));
	    do
       		#initial conditions for DoS attack
		condition1_DoS=$(tshark -r ".80.pcap" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.srcport" 2> /dev/null | sort | uniq | wc -l)
		condition2_DoS=$(tshark -r ".80.pcap" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.flags" 2> /dev/null | wc -l)
		
		for file in "${captures[@]}"
		do
		    condition1_scan=$(tshark -r "${file}" -Y "tcp.flags == 0x002 || tcp.flags == 0x012 || tcp.flags == 0x010" -T fields -e "tcp.seq" 2> /dev/null | wc -l)
		    condition2_scan=$(tshark -r "${file}" -Y "tcp.flags == 0x002 || tcp.flags == 0x012 || tcp.flags == 0x010" -T fields -e "tcp.ack" 2> /dev/null | wc -l)
		    
		    if [[ "$condition1_scan" -gt 0 || "condition2_scan" -gt 0 ]];
		    then
			echo "[ALERT] ! ==> Port Scan detected."
			port_scan
		    fi
		done
		    
		if [ "${ports[$j]}" == '80' ];
		then
	            if [[ "$condition1_DoS" -gt 100 || "$condition2_DoS" -gt 100 ]];
	            then
     			echo "[ALERT] ! ==> Possible DoS attack detected."
			denial_of_service
		    fi
		fi
		
		if [ "${ports[$j]}" == '21' ];
		then
		    continue
		fi

		if [ "$cleanFiles" -eq 0 ];
		then
		    clean_files
		fi
	    done
	    if [ "$i" -eq 10 ];
	    then
		clean_files
		sleep 10
            fi
	done
    done
}

echo "[+] sniffing"
detector
