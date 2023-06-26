#!/bin/bash

#importar main

general_capture='.general.pcap'
predefined_ports=('21' '22' '23' '25' '80' '443' '445' '1433')
ports=()
captures=()
interfaces=$(ifconfig | awk '{print $1}' | grep ':' | tr -d ':')
local_ip=$(ifconfig enp4s0 | grep 'inet ' | awk '{print $2}')
flag=0
n_elements=0;

pid1=0;
pid2=0;

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

    n_elements="${#ports[@]}"
}

function sniffer() {

    tshark -w "${general_capture}" -i enp4s0 2> /dev/null &
    pid1=$!
}

function filters() {
    
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
		done
	    done
	fi
    done
}

function denial_of_service() {

    id_DoS=1
    file="DoS-${id_DoS}.pcap"
    
    init_value=$(tshark -r '.80.pcap' 2> /dev/null | awk '{print $1}' | head -n 1)
    sleep 30
    final_value=$(tshark -r '.80.pcap' 2> /dev/null | awk '{print $1}' | tail -n 1)

    while [ -f $file ];
    do
	id_DoS=$((id_DoS+1))
    done
    
    tshark -w "${file}" -r '.80.pcap' -Y "frame.number >= ${init_value} && frame.number <= ${final_value}" 2> /dev/null
    echo "pcap creado"
    flag=1
}

function clean_files() {
    
    if [ "$flag" -eq 1 ];
    then
	echo "eliminando"
	truncate --size 0 $general_capture
	echo "listo"
	sniffer
	flag=0
    fi
}

function detector() {

    syn=0
    array=()

    port_scanner
    sniffer
    filters &
    pid2=$!

    for i in "${captures[@]}"
    do
	echo $i
    done
    
    while true;
    do
        for (( k=0;k<=$n_elements;k++ ));
	do
	    if [ "$flag" -eq 0 ];
	    then
		if [ "${ports[$k]}" == '80' ];
		then
		    #initial condition
		    port="${ports[$k]}"
		    input1=$(tshark -r ".80.pcap" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.srcport" 2> /dev/null | sort | uniq | wc -l)
		
		    if [ "$((input1))" -gt 1 ];
		    then
			echo "dos detectado"
			denial_of_service
			clean_files
		    fi
		fi

		if [ "${ports[$k]}" == '21' ];
		then
		    echo ""
		fi

		if [ "${ports[$k]}" == '22' ];
		then
		    echo ""
		fi
	    fi
	done
    done

}

echo "[+] sniffing"
detector

wait $pid1
wait $pid2



