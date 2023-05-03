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

#variables
current=$PWD
new_directory="PCAPS"
flag=0
flag2=0
instalation=0
id_file=1

name_option=""
name_suboption=""

#options in main menu
declare -A options
options=(
    ["pcap_analyze"]=1
    ["sniffing"]=2
    ["packet_manipulation"]=3
    ["layer2_attacks"]=4
    ["malicious_ip"]=5
    ["exit"]=6
)

#options in pcap analyzer
declare -A options_pcap_analyzer
options_pcap_analyzer=(
    ["tcp_syn_flood"]=1
    ["nmap_scan"]=2
    ["vlan_hopping"]=3
    ["hsrp_attack"]=4
    ["tcp_port_scan"]=5
    ["ARP_spoofing"]=6
    ["DHCP_spoofing"]=7
    ["Back"]=8
)

function frame() {
    
    repeat="."
    for (( i=0;i<=70;i++ ))
    do
	echo -n "$repeat"
    done
}

#main banner
function banner() {
    echo -e "${green}"
    echo -e '      ________  ______   ______             _____  __________   ________'
    echo -e '     /   ____/ /  __  \ /  ____\   _____   /     \ \_____    \ /   ____/'
    echo -e '     \____   \ |  ____/ \  \____   |____|    ---     |    ___/ \____   \ '
    echo -e "     /_______/ \_____>   \______\          \_____/   |    |    /_______/      ${cyan}By: Luis Herrera :)${green}"
    echo -e "                                                     |____|                   ${cyan}V.1.0"
    echo -e "${red}"
    echo -e " +-------------------------------------------------------------------------------------------------------------+"
    echo -e " | Speed up the process of detecting basic attacks from a pcap file                                            |"
    echo -e " | and streamline the processes of attacks to local networks.                                                  |"
    echo -e " +-------------------------------------------------------------------------------------------------------------+"
    echo -e "${default}"
}

#prompt
function prompt_option() {
    echo -e "\n${green}┌─[${red}${HOSTNAME}${green}]──[${red}~${green}]─[${yellow}/MainMenu/${name_option}/${green}]:"
}

function prompt_suboption() {
    echo -e "${green}┌─[${red}${HOSTNAME}${green}]──[${red}~${green}]─[${yellow}/MainMenu/PcapAnalyzer/${name_suboption}${green}]:"
}

#errors
function error_option() {
    echo -e "${red}\n ERROR, the specified option does not exist!\n\n${default}"
}

function error_load_pcap() {
    echo -e "${red}\n ERROR, the specified PCAP file does not exist!..\n\n${default}"
}

function error_instalation() {
    echo -e "${red}\n [+] ERROR, an unexpected error occurred during installation!!${default}"
}

#checking required tools
function tool_check() {

    required_tools=(
        'tshark'
        'scapy'
        'yersinia'
    )

    tool_check=0
    no_tool=()

    echo -e "${yellow}\n [+] Checking required tools.....${default}"
    sleep 0.2

    for i in "${required_tools[@]}"
    do
        if [[ $(which $i) ]];
        then
            echo -e "\n${green} [$i] ${red}Tool is installed $(frame) ${green}[OK]${default}"
            sleep 0.2

        else
            echo -e "\n${green} [$i] ${red}Tool is installed $(frame) [ERROR]${default}"
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

            if [ $(`grep -i "debian" /etc/*-release`) ];
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
function pcap_analyzer_option_1() {
    load_pcap
    detect_tcp_syn_flood
}

function pcap_analyzer_option_2() {
    load_pcap
}

function pcap_analyzer_option_3() {
    load_pcap
}

function pcap_analyzer_option_4() {
    load_pcap
}

function pcap_analyzer_option_5() {
    load_pcap
}

function pcap_analyzer_option_6() {
    load_pcap
}

function pcap_analyzer_option_7() {
    load_pcap
}

function pcap_analyzer_option_8 () {
    main_menu
}

function detect_tcp_syn_flood() {
    
    echo -e "\n${green} [+] ${count}Getting ready......${default}"

    #Extract number of total TCP packets in pcap
    total_packets=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp && tcp.window_size <= 1000" 2> /dev/null | wc -l)

    if [ "$((total_packets))" -gt 100000 ];
    then
	limit=100000
	echo -e "\n\n${green} [+] ${count}Examining 100,000 packets, wait a moment.${default}"

    else
	limit=$((total_packets))
	echo -e "\n\n${green} [+] ${count}Examining ${total_packets} packets, wait a moment${default}"
    fi

    #Extract impacted port(s)
    dstports=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.window_size < 1000 && frame.number <= ${limit}" -T fields -e "tcp.dstport" 2> /dev/null | sort | uniq)
    dstports_array=($dstports)

    #Extract impacted host
    dstip=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e "ip.dst" 2> /dev/null | head -n 1)

    requests_array=()
    ports_array=()
    ips_array=()

    n_elements="${#dstports_array[@]}"
    
    for (( i=0;i<=n_elements-1;i++ ))
    do

	port="${dstports_array[$i]}"
	
	#Extract total SYN requests in each port
	syn=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == ${port} && tcp.window_size < 1000 && frame.number <= ${limit}" 2> /dev/null | wc -l)
	syn_array+=("$syn")
	
	#Extract total ACK replys in each port
	ack=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 1 && tcp.srcport == ${port} && frame.number <= ${limit}" -T fields -e "tcp.srcport" 2> /dev/null | wc -l)
	ack_array+=("$ack")

        fiveseconds=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == ${port} && tcp.window_size < 1000 && frame.number <= ${limit}" 2> /dev/null | awk '{print $2}' | awk -F'.' '{print $1}')
	fiveseconds_array=($fiveseconds)

	requests=0
	start_second="${fiveseconds_array[0]}"
   
        for second in "${fiveseconds_array[@]}"
        do
	    requests=$((requests+1))
	    
	    if [ "$second" == "$((start_second+5))" ];
	    then
		break
	    fi
	done
	
        requests_array+=("$requests")
        unset fiveseconds_array[*]

	srcports=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == ${port} && tcp.window_size < 1000 && frame.number <= ${limit}" -T fields -e "tcp.srcport" 2> /dev/null)
	srcports_array=($srcports)

	ports=0
	last_port="${srcports_array[0]}"
    
	for port in "${srcports_array[@]}"
	do
	    current_port=$((port))

	    if [ "$((last_port+1))" -eq "$((current_port))" ];
	    then
		ports=$((ports+1))
	    fi

	    last_port=$((port))
	done

	ports_array+=("$ports")
	unset srcports_array[*]

	srcip=$(tshark -r $new_directory/capture-$id_file.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == ${port} && tcp.window_size < 1000 && frame.number <= ${limit}" -T fields -e "ip.src" 2> /dev/null)
	srcip_array=($(echo "$srcip" | tr ' ' '\n'))
	
	ips=0
	last_ip="${srcip_array[0]}"
    
	for ip in "${srcip_array[@]}" 
	do
	    current_ip=$ip

	    if [ "$current_ip" != "$last_ip" ];
	    then
		ips=$((ips+1))
	    fi

	    last_ip=$ip
	done
    
       ips_array+=("$ips")
       unset srcip_array[*]

    done

    points=0
    echo -e "\n${green} $(frame)\n  RESULTS \n $(frame) ${default}"
    echo -e "\n${yellow}  [+] Host impacted ===> ${green}${dstip} ${default}"
    
    for (( i=0;i<=$n_elements-1;i++ ))
    do
	
	port="${dstports_array[$i]}"
	
	echo -e "\n${green} $(frame)${default}"
	echo -e "\n${yellow}  [+] Port impacted ===> ${red}${port} ${default}"
	echo -e "\n${green} $(frame)${default}"

	if [ "${syn_array[$i]}" -gt 5000 ];
	then
	    echo -e "\n${yellow}  [+] Total SYN Requests: ${red}${syn_array[$i]} [!]${default}"

	    if [ "${ack_array[$i]}" -lt "${syn_array[$i]}" ];
	    then
		echo -e "\n${yellow}\t[+] Ack Replys: ${red}${ack_array[$i]} [!]${default}"

		if [ "${ports_array[$i]}" -gt 500 ];
		then
		    echo -e "\n${yellow}\t[+] Consecutive source ports: ${red}${ports_array[$i]} [!]${default}"
		    
		else
		    echo -e "\n${yellow}\t[+] Consecutive source ports: ${green}${ports_array[$i]}${default}"
		fi

		if [ "${ips_array[$i]}" -gt 500 ];
		then
		    echo -e "\n${yellow}\t[+] Different IP addresses : ${red}${ips_array[$i]} [!]${default}"
		    
		else
		    echo -e "\n${yellow}\t[+] Different IP addresses : ${green}${ips_array[$i]}${default}"
		fi

		if [ "${requests_array[$i]}" -gt 1000 ];
		then
		    echo -e "\n${yellow}  [+] SYN Requests in 5 seconds: ${red}${requests_array[$i]} [!]${default}"
		    
		else
		    echo -e "\n${yellow}  [+] SYN Requests in 5 seconds: ${green}${requests_array[$i]}${default}"
		fi
		
	    else
		echo -e "\n${yellow}  [+] Ack Replys: ${green}${ack_array[$i]}${default}"
	    fi
	       
	else
	    echo -e "\n${yellow}  [+] Total SYN Requests: ${green}${syn_array[$i]}${default}"
	fi
	
    done

    echo -e "\n${green} $(frame)${default}"
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

                echo -e "\n${green} [+] Correct! File selected ==> ${path} \n"
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
    echo -e "\n\n ${yellow}[OPTIONS] \n\n${green} [1] TCP SYN Flood\n\n [2] Nmap Scan \n\n [3] Vlan Hopping\n\n [4] HSRP Attack\n\n [5] TCP Port Scan\n\n [6] ARP Spoofing\n\n [7] DHCP Spoofing\n\n [8] Back \n\n ${default}"
    echo -e "${yellow} Please, enter a option${default}\n"

    while [ "$flag" -eq 0 ];
    do
        prompt_option
        read -p "└─────► $(tput setaf 7)" suboption

        if [[ "$suboption" -gt 8 || "$option" -lt 1 ]];
        then
            flag2=1

        else
            flag2=0
        fi

        if [ "$flag2" -eq 0 ];
        then
            for key in "${!options_pcap_analyzer[@]}";
            do
                value="${options_pcap_analyzer[$key]}"
                name_suboption=$key

                if [ "$suboption" == "$value" ];
                then
                    pcap_analyzer_option_${value}
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
function main_menu_option_6() {

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
    echo -e "\n\n ${yellow}[OPTIONS] \n\n${green} [1] PCAP Analyze\n\n [2] Sniffing\n\n [3] Packet Manipulation\n\n [4] Layer 2 Attacks\n\n [5] Malicious Ip\n\n [6] Exit\n\n ${default}"
    echo -e "${yellow} Please, enter a option${default}\n"

    while [ "$flag" -eq 0 ];
    do
        echo -e "\n${green}┌─[${red}${HOSTNAME}${green}]──[${red}~${green}]─[${yellow}/MainMenu/${green}]:"
        read -p "└─────► $(tput setaf 7)" option

        if [[ "$option" -gt 6 || "$option" -lt 1 ]];
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

