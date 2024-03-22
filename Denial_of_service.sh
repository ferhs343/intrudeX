#!/bin/bash

source Secops/secops.sh

function slowloris() {

    echo -e "\n${green} [+] Slowloris Test .....${default}"
  
    #extract host impacted
    host_impacted=$(tshark -r $new_directory/capture-$id_file.pcap -Y "${conditions[0]} && ${conditions[3]}" -T fields -e "${groups[1]}" 2> /dev/null | head -n 1)
    
    #extract port impacted
    port_impacted=$(tshark -r $new_directory/capture-$id_file.pcap -Y "${conditions[0]} && ${conditions[3]}" -T fields -e "${groups[3]}" 2> /dev/null | sort | uniq | grep '80\|443')
    array=($port_impacted)
    
    #extract total of TCP packets
    input1=$(tshark -r $new_directory/capture-$id_file.pcap -Y "${protocols[0]}" -T fields -e "${groups[2]}" 2> /dev/null | wc -l)
    value=$((input1))

    if [ "$((input1))" -gt 100000 ];
    then
	limit=100000
	
    else
	limit=$((input1))
    fi

    #extract seconds values 
    input2=$(tshark -r $new_directory/capture-$id_file.pcap -Y "${protocols[0]}" 2> /dev/null | awk '{print $2}' | head -n $limit | awk -F'.' '{print $1}')
    array1=($input2)

    begin="${array1[0]}"
    n_elements="${#array1[@]}"

    #extract number of source ports
    input3=$(tshark -r $new_directory/capture-$id_file.pcap -Y "${conditions[0]} && ${conditions[3]}" -T fields -e "${groups[2]}" 2> /dev/null | head -n $limit | sort | uniq | wc -l)

    #extract source ports
    input4=$(tshark -r $new_directory/capture-$id_file.pcap -Y "${protocols[0]}" -T fields -e "${groups[2]}" 2> /dev/null | head -n $limit)
    array2=($input4)

    #extract flags
    input5=$(tshark -r $new_directory/capture-$id_file.pcap -Y "${protocols[0]}" -T fields -e "${groups[4]}" 2> /dev/null | head -n $limit | tr -d '[0x]')
    array3=($input5)

    #extract sequence numbers
    input6=$(tshark -r $new_directory/capture-$id_file.pcap -Y "${protocols[0]}" -T fields -e "${groups[6]}" 2> /dev/null | head -n $limit)
    array4=($input6)

    #extract Acknowledgment
    input7=$(tshark -r $new_directory/capture-$id_file.pcap -Y "${protocols[0]}" -T fields -e "${groups[7]}" 2> /dev/null | head -n $limit)
    array5=($input7)
    
    #detect openned conections in 5 seconds
    openned=0
    array6=()

    syn=1
    synack=1
    handshake=False

    #extract the number of conections established, examining 3 way handshake
    if [ "$input3" -gt 1 ];
    then
	for (( i=0;i<=$n_elements-1;i++ ))
	do
	    if [ "${array3[$i]}" == "2" ];
	    then
		syn=0
		seq1="${array4[$i]}"

	    elif [ "${array3[$i]}" == "12" ]
	    then
		if [ "$syn" -eq 0 ];
		then
		    ack1="${array5[$i]}"
		    
		    if [ "$((ack1))" -eq "$((seq1+1))" ];
		    then
			synack=0
			seq2="${array4[$i]}"
		    fi
		fi

	    elif [ "${array3[$i]}" == "1" ];
	    then
		if [ "$synack" -eq 0 ];
		then
		    ack2="${array5[$i]}"

		    if [ "$((ack2))" -eq "$((seq2+1))" ];
		    then
			handshake=True
		    fi
		fi
	    fi

	    if [ "$handshake" == "True" ];
	    then
		openned=$((openned+1))
		array6+=("${array2[$i]}")
		syn=1
		synack=1
		handshake=False
	    fi
		    
	    if [ "${array1[$i]}" == "$((begin+5))" ];
	    then
		break
	    fi
	done

        n_elements="${#array6[@]}"

	#extract anomalies of TCP segments of one source port selected
	if [ "$openned" -gt 15 ];
	then
	    test=$(($n_elements / 2 | bc))
	    input8=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.port == ${array6[$test]} && ${conditions[4]}" -T fields -e "${groups[5]}" 2> /dev/null)
	    array7=($input8)
	    n_elements="${#array7[@]}"

	    input9=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.port == ${array6[$test]}" 2> /dev/null | awk '{print $2}' | awk -F'.' '{print $1}')
	    array8=($input9)
	    start="${array8[0]}"
	    end="${array8[-1]}"
	    time=$((end-start))
	    count_data=0
	    
	    for (( i=0;i<=$n_elements;i++ ))
	    do
		if echo "${array7[$i]}" | grep "474554202f3f" 1> /dev/null;
		then
		    method=$(echo -n "${array7[$i]}" | xxd -r -p | head -n 1)

		    if echo "${array7[$i]}" | grep "57696e646f7773204e5420352e31" 1> /dev/null;
		    then
			user_agent="Windows NT 5.1"
		    fi
	        fi

		if echo "${array7[$i]}" | grep "582d613a20620d0a" 1> /dev/null;
		then
		    data="X-a: b"
		    count_data=$((count_data+1))
	        fi
	    done
	fi

	if [ "$n_elements" -ge 1 ];
	then
	    if echo "$method" | grep "GET /?" 1> /dev/null;
	    then
		if [ "$count_data" -gt 1 ];
		then
		    if [ "$time" -gt 10 ];
		    then
			echo -e "\n${red} ALERT! Slowloris technique attack detected!${default}"
			sleep 1
			echo -e "\n${green} [+] Loading details .....${default}"
			sleep 1
			techniques_verif=True
      		    fi
		fi
	    fi
	fi

	if [ "$techniques_verif" == "False" ];
	then
	    syn_flood
	    
	else
	    echo -e "${green}\n $(frame -)\n ${yellow} [+] Impact: ${green}${host_impacted}:${port_impacted} ${green}\n $(frame -) ${default}"
	    echo -e "\n${yellow}  [+] Openned connections in 5 seconds: ${green}${openned}${default}"
	    echo -e "\n${yellow}  [+] Source port analyzed: ${green}${array6[$test]}${default}"
	    echo -e "\n${yellow}\t[+] Connection time duration: ${green}${time}s${default}"
	    echo -e "\n${yellow}\t[+] Request: ${green}${method} ${default}"
	    echo -e "\n${yellow}\t[+] User-agent: ${green}${user_agent}${default}"
	    echo -e "\n${yellow}\t[+] TCP Segment data: ${green}${data}${default}"
	    echo -e "\n${green} $(frame -)${default}"
	fi
	
    else
        echo -e "\n\n${green} [+] SecOps dont found anomalies.${default}\n"
    fi		     

}

function syn_flood() {
    echo "pasaste a tcp syn flood"
}

function detect_Denial_of_service() {

    #    hping3                     scapy                    slowloris           
    # un origen                   un origen                  un origen         
    # spoofing                    spoofing                                    
    # cualquier puerto(s)         cualquier puerto(s)            
    # tamaño de ventana -         tamaño de ventana -         
    # repuestas < solicitudes     respuestas < solicitudes                       
    # miles de requets            miles de requests                             
    #                                                        solo al puerto 80 o 443
    #                                                        user agent: windows xp
    #                                                        carga util
    #                                                        psh,ack GET
    #                                                        miles de conexiones abiertas
    #                                                        error 400

    icmp=$(tshark -r  $new_directory/capture-$id_file.pcap -Y "icmp" -T fields -e "ip.src" 2> /dev/null | wc -l)
    tcp=$(tshark -r  $new_directory/capture-$id_file.pcap -Y "tcp" -T fields -e "ip.src" 2> /dev/null | wc -l)
    udp=$(tshark -r  $new_directory/capture-$id_file.pcap -Y "udp" -T fields -e "ip.src" 2> /dev/null | wc -l)

    if [[ "$((icmp))" -gt "$((tcp))" && "$((icmp))" -gt "$((udp))" ]];
    then
	echo -e "\n\n${green} [+] Examining ICMP......${default}\n"
	
    elif [[ "$((tcp))" -gt "$((icmp))" && "$((tcp))" -gt "$((udp))" ]];
    then

	input2=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "tcp.dstport" 2> /dev/null | sort | uniq)
	array1=($input2)
     
	n_elements="${#array1[@]}"

	if [ "$n_elements" -gt 0 ];
	then
	    for i in "${array1[@]}"
	    do
		if [[ "$i" == '80' || "$i" == '443' ]];
		then
		    slowloris
		    
		else
		    syn_flood
		fi
	    done
	    
	else
	    echo -e "\n${red} [+] ERROR, there are no TCP packets to analyze!.${default}\n"
	fi

    elif [[ "$((udp))" -gt "$((icmp))" && "$((udp))" -gt "$((tcp))" ]];
    then
	echo -e "\n\n${green} [+] Examining UDP......${default}\n"
    fi
  
}
