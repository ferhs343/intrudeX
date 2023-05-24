#!/bin/bash
#
# SEC-OPS
# --------
# Herramienta para detectar ataques básicos a redes en archivos pcap.
# Luis Herrera, Abril 2023

clear

#colors
default="\033[0m\e[0m"
yellow="\e[1;93m"
red="\e[1;91m"
cyan="\e[1;94m"
green="\e[1;92m"
purple="\e[1;95m"

#global variables
current=$PWD
new_directory="PCAPS"
flag=0
flag2=0
instalation=0
id_file=1
techniques_verif=False
name_option=""
name_suboption=""

#main menu
declare -A options
options=(
    ["Attack_detection"]=1
    ["Reconnaissance_detection"]=2
    ["Threat_intelligence"]=3
    ["exit"]=4
)

#menu pcap analyzer
declare -A options_attack_detection
options_attack_detection=(
    ["Denial_of_service"]=1
    ["Web_attacks"]=2
    ["Brute_force"]=3
    ["DNS_tunneling"]=4
    ["LAN_attacks"]=5
    ["Back"]=6
)

#filters in thsark
protocols=(
    'tcp'
    'http'
)

conditions=(
    'tcp.flags.syn == 1'
    'tcp.flags.syn == 0'
    'tcp.flags.ack == 1'
    'tcp.flags.ack == 0'
    'tcp.flags.push == 1'
    'tcp.dstport == 80'
    'tcp.dstport == 443'
    'tcp.flags == 0x018'
    'tcp.flags == 0x002'
    'tcp.flags == 0x010'
)

groups=(
    'ip.src'
    'ip.dst'
    'tcp.srcport'
    'tcp.dstport'
    'tcp.flags'
    'tcp.segment_data'
    'tcp.seq'
    'tcp.ack'
)

function frame() {
    
    for (( i=0;i<=70;i++ ))
    do
	echo -n $1
    done
}

#main banner
function banner() {
    echo -e "${green}"
    echo -e '      ________  ______   ______             _____  __________   ________'
    echo -e '     /   ____/ /  __  \ /  ____\   _____   /     \ \_____    \ /   ____/'
    echo -e '     \____   \ |  ____/ \  \____   |____|    ---     |    ___/ \____   \ '
    echo -e "     /_______/ \_____>   \______\          \_____/   |    |    /_______/  \t\t ${cyan}By: Luis Herrera :)${green}"
    echo -e "                                                     |____|               \t\t ${cyan}V.1.0"
    echo -e "${red}"
    echo -e " +-------------------------------------------------------------------------------------------------------------+"
    echo -e " | Speed up the process of detecting basic attacks from a pcap file and streamline                             |"
    echo -e " | the processes of attacks to local networks.                                                                 |"
    echo -e " +-------------------------------------------------------------------------------------------------------------+"
    echo -e "${default}"
}

#prompt
function prompt_option() {
    echo -e "\n${green}┌─[${red}${HOSTNAME}${green}]──[${red}~${green}]─[${yellow}/MainMenu/${name_option}/${green}]:"
}

function prompt_suboption() {
    echo -e "${green}┌─[${red}${HOSTNAME}${green}]──[${red}~${green}]─[${yellow}/MainMenu/${name_option}/${name_suboption}${green}]:"
}

#errors
function error_option() {
    echo -e "${red}\n ERROR, the specified option does not exist!!\n\n${default}"
}

function error_load_pcap() {
    echo -e "${red}\n ERROR, the specified PCAP file does not exist!!\n\n${default}"
}

function error_instalation() {
    echo -e "${red}\n [+] ERROR, an unexpected error occurred during installation!!${default}"
}

#checking required tools
function tool_check() {

    required_tools=(
        'tshark'
        'wget'
        'curl'
	'jq'
    )

    tool_check=0
    no_tool=()

    echo -e "${yellow}\n [+] Checking required tools.....${default}"
    sleep 0.2

    for i in "${required_tools[@]}"
    do
        if [[ $(which $i) ]];
        then
            echo -e "\n${green} [$i] ${red}Tool is installed $(frame .) ${green}[OK]${default}"
            sleep 0.2
        else
	    
            echo -e "\n${green} [$i] ${red}Tool is installed $(frame .) [ERROR]${default}"
            tool_check=1
            no_tool+=("$i")
            sleep 1
        fi
    done

    if [ "$tool_check" -eq 1 ];
    then
        for tool in "${no_tool[@]}"
        do
            echo -e "${yellow}\n\n [+] Installing Tool ${green}(${tool})${yellow}, wait a moment.....${default}"

            if [ $(grep -i "debian" /etc/*-release) ];
            then
                sudo apt-get install -fy $tool &>/dev/null

            elif [ $(grep -i "arch" /etc/*-release) ];
            then
                sudo pacman -Syu $tool >/dev/null 2>&1

            elif [ $(grep -i "cent0S" /etc/*-release) ];
            then
                sudo yum -y install $tool >/dev/null 2>&1
            fi

            if [ "$?" -eq 0 ];
            then
                echo -e "${green}\n [+] Installation complete.${default}"
                sleep 1
            else
		
                error_instalation
                sleep 2
                main_menu_option_6
            fi
        done

        echo -e "${green}\n\n [+] Reloading......${default}"
        sleep 2
        main_menu
    fi
}

#pcap analyzer options
function attack_detection_option_1() {
    load_pcap
}

function attack_detection_option_2() {
    load_pcap
}

function attack_detection_option_3() {
    load_pcap
}

function attack_detection_option_4() {
    load_pcap
}

function attack_detection_option_5() {
    load_pcap
}

function attack_detection_option_6() {
    main_menu
}

# -------------------------------------------------------------------- Denial Of Service --------------------------------------------------------------------
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
	    alert=$(echo -e "${red}[!]${default}")
	    test=$(($n_elements / 2 | bc))
	    input8=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.port == ${array6[$test]} && ${conditions[4]}" -T fields -e "${groups[5]}" 2> /dev/null)
	    array7=($input8)
	    n_elements="${#array7[@]}"

	    input9=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.port == ${array6[$test]}" 2> /dev/null | awk '{print $2}' | awk -F'.' '{print $1}')
	    array8=($input9)
	    start="${array8[0]}"
	    end="${array8[-1]}"
	    time=$((end-start))

	    for (( i=0;i<=$n_elements;i++ ))
	    do
		if echo "${array7[$i]}" | grep "474554202f3f" 1> /dev/null;
		then
		    method="GET"

		    if echo "${array7[$i]}" | grep "57696e646f7773204e5420352e31" 1> /dev/null;
		    then
			user_agent="Windows NT 5.1"

		    else
			user_agent=$(echo "${array7[$i]}" | xxd -r -p | grep 'User-Agent:' | tr 'User-Agent: ' '')
		    fi
	        fi

		if echo "${array7[$i]}" | grep "582d613a20620d0a" 1> /dev/null;
		then
		    data="X-a: b"
	        fi
	    done
	fi

	if [ "$n_elements" -ge 5 ];
	then
	    if [ "$method" == "GET" ];
	    then
		if [ "$time" -gt 10 ];
		then
		    techniques_verif=True
		fi
	    fi
	fi

	if [ "$techniques_verif" == "False" ];
	then
	    syn_flood
	    
	else
	    echo -e "${green}\n $(frame -)\n ${yellow} [+] Impact: ${green}${host_impacted}:${port_impacted} ${green}\n $(frame -) ${default}"
	    echo -e "\n${red}  ALERT! Slowloris technique attack detected!${default}"
	    echo -e "\n${yellow}  [+] Openned connections in 5 seconds: ${green}${openned} ${alert}${default}"
	    echo -e "\n${yellow}  [+] Source port analyzed: ${green}${array6[$test]}${default}"
	    echo -e "\n${yellow}\t[+] Connection time duration: ${green}${time}s${default}"
	    echo -e "\n${yellow}\t[+] TCP Flag: ${green}PUSH${default}"
	    echo -e "\n${yellow}\t[+] HTTP Method: ${green}${method}${default}"
	    echo -e "\n${yellow}\t[+] User-agent: ${green}${user_agent} ${alert}${default}"
	    echo -e "\n${yellow}\t[+] TCP Segment data: ${green}${data} ${alert}${default}"
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
	echo -e "\n\n${green} [+] Examining ${n_elements} ports .....${default}\n"

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

#load pcap files
function load_pcap() {

    clear
    banner
    echo -e "\n\n ${yellow}[OPTIONS] \n\n${green} [1] Back \n${default}"
    check=0

    while [ "$check" -eq 0 ];
    do
        echo -e "\n${yellow} Enter the path of PCAP file to analyze.${default}\n"
        prompt_suboption
        read -p "└─────► $(tput setaf 7)" path
	
        if [ "$path" == "1" ];
        then
            main_menu_option_1
            check=1
        else
	    
            echo -e "\n${green} [+] Finding ${path} .....${default}\n"
            sleep 2

            if [ -f "$path" ];
            then

                while [ -f $current/$new_directory/capture-$id_file.pcap ];
                do
                    id_file=$((id_file+1))
                done

                cp $path $current/$new_directory/capture-$id_file.pcap

                echo -e "\n${green} [+] Getting ready ....."
		sleep 1
                detect_${name_suboption}
                check=1
            else
		
                error_load_pcap
                check=0
            fi
        fi
	
        if [ "$check" -eq 1 ];
        then
            echo -e "\n\n${yellow} Please, if you analyze other PCAP file, enter de path of this, otherwise, press 1 for back.${default}\n"
            check=0
        fi
    done
}

#option 1 in main menu
function main_menu_option_1() {

    flag=0
    clear
    banner
    echo -e "\n\n ${yellow}[OPTIONS] \n\n${green} [1] Denial of Service\n\n [2] Web Attacks \n\n [3] Brute Force\n\n [4] DNS Tunneling\n\n [5] LAN Attacks\n\n [6] Back \n\n ${default}"
    echo -e "${yellow} Please, enter a option${default}\n"

    while [ "$flag" -eq 0 ];
    do
        prompt_option
        read -p "└─────► $(tput setaf 7)" suboption

        if [[ "$suboption" -gt 6 || "$option" -lt 1 ]];
        then
            flag2=1
        else
	    
            flag2=0
        fi

        if [ "$flag2" -eq 0 ];
        then
            for key in "${!options_attack_detection[@]}";
            do
                value="${options_attack_detection[$key]}"
                name_suboption=$key

                if [ "$suboption" == "$value" ];
                then
                    attack_detection_option_${value}
                    flag=1
                fi
            done
        else
	    
            error_option
            flag=0
            flag2=0
        fi
    done
}

#exit
function main_menu_option_4() {

    echo -e "\nBYE!.\n"
    sleep 1
    clear
    exit
    flag=0
}

#main menu
function main_menu() {

    flag=0
    clear
    banner
    tool_check
    echo -e "\n\n ${yellow}[OPTIONS] \n\n${green} [1] Attack detection\n\n [2] Reconnaissance detection\n\n [3] Threat Intelligence\n\n [4] Exit\n\n ${default}"
    echo -e "${yellow} Please, enter a option${default}\n"

    while [ "$flag" -eq 0 ];
    do
        echo -e "\n${green}┌─[${red}${HOSTNAME}${green}]──[${red}~${green}]─[${yellow}/MainMenu/${green}]:"
        read -p "└─────► $(tput setaf 7)" option

        if [[ "$option" -gt 4 || "$option" -lt 1 ]];
        then
            flag2=1
        else
	    
            flag2=0
        fi

        if [ "$flag2" -eq 0 ];
        then
            for key in "${!options[@]}";
            do
                value="${options[$key]}"
                name_option=$key
		
                if [ "$option" == "$value" ];
                then
                    main_menu_option_${value}
                    flag=1
                fi
            done
        else

            error_option
            flag=0
            flag2=0
        fi
    done
}

#main program

if [[ ! -d $new_directory ]];
then
    mkdir $new_directory
fi

main_menu


