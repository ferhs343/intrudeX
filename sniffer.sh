#!/bin/bash

#importar main

general_capture='.general.pcap'
ports=('443' '80')
captures=()

local_ip=$(ifconfig eth0 | grep 'inet ' | awk '{print $2}')
flag=0

function port_scanner() {
    
    for (( i=0;i<=49151;i++ ))
    do
        nc -zvn 127.0.0.1 $i 2> /dev/null
	
	if [ "$?" -eq 0 ];
	then
	    ports+=("$i")
	fi
    done

    echo "puertos listos"
}

function denial_of_service() {

    echo "${initial_value}"
    
    sleep 60

    value2=$(tshark -r "${general_capture}" -Y "ip.addr == ${local_ip} && tcp.port == ${port}" 2> /dev/null | awk '{print $1}' | tail -n 1)
    final_value=$value2

    echo "${final_value}"

    tshark -w "dos.pcap" -r "${file}" -Y "ip.addr == ${local_ip} && tcp.port == ${port} && frame.number >= ${initial_value} && frame.number <= ${final_value}" 2> /dev/null
    flag=1
    echo "la bandera ya vale 1"
    #investigar como finalizar una funcion en segundo plano
}


#se ejecutara tshark en segundo plano
#al entrar a cualquier opcion del menu de ataques, se deberan mostrar ciertos "logs" y el input para cargar ciertos pcaps a analizar, si asi se desea

#escanear puertos, para saber que se debe monitorear
#sniffear trafico y filtrar por cada puerto

#primero aplicar filtros que corresponden a un ataque en particular, iniciando por un indicador inicial, por ejemplo, numero de solicitudes syn
#despues ir analizando los paquetes
#obtener numero de paquete, para empezar a analizar desde ahi

function sniffer() {

    port_scanner
    tshark -w "${general_capture}" -i eth0 2> /dev/null &

    for (( i=0;i<=$n_elements;i++ ));
    do
	captures+=(".${ports[$i]}.pcap")
	
        if [ "$i" -eq "$n_elements" ];
	then
	    while true;
	    do
		for (( j=0;j<=$n_elements;j++ ));
		do
		    tshark -w "${captures[$j]}" -r "${general_capture}" -Y "tcp.port == ${ports[$j]}" 2> /dev/null
		done
	    done
	fi
    done
}

function detector() {

    syn=0
    array=()
    n_elements="${#ports[@]}"

    sniffer &
    
    while true;
    do
        for (( i=0;i<=$n_elements;i++ ))
	do
	    if [ "$flag" -eq 0 ];
	    then	
		if [ "${ports[$i]}" == '443' ];
		then
		    echo ""
		    #input1=$(tshark -r "${general_capture}" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.addr == ${local_ip} && tcp.port == ${ports[$i]}" -T fields -e "tcp.srcport" 2> /dev/null | sort | uniq | wc -l)
		   # port="${ports[$i]}"

		   # sleep 2
		
		   # if [ "$((input1))" -gt 1 ];
		    #then
		#	value=$(tshark -r "${general_capture}" -Y "ip.addr == ${local_ip} && tcp.port == ${port}" 2> /dev/null | awk '{print $1}' | tail -n 1)
		#	initial_value=$value
		#	denial_of_service
		 #   fi
		fi
	    fi

	    if [ "$flag" -eq 1 ];
	    then
		echo "eliminando"
		truncate --size 0 $file
		echo "listo"
	 	sniffer
		flag=0
	    fi
	    
	    sleep 10
	done
    done

}

echo "[+] Sniffing..."

detector


