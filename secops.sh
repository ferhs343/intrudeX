#!/bin/bash
#
# SEC-OPS
# --------
# Herramienta con múltiples utilidades para equipos de respuesta a incidentes.
#    - Detección de ataques más comunes a nivel de capa de aplicación, así como a nivel de capa 2
#    - Detección de reconocimiento a la infraestructura
#    - Utilidades para la ejecución de Threat Intellingece
# Luis Herrera, Abril 2023

#colors
default="\033[0m\e[0m"
yellow="\e[1;93m"
red="\e[1;91m"
cyan="\e[1;94m"
green="\e[1;92m"
purple="\e[1;95m"

#global variables
current=$PWD
directory="PCAPS"
flag=0
flag2=0
instalation=0
id_file=1
name_option=""
name_suboption=""

subdirectories=(
    'External_Pcaps'
    'Denial_of_Service'
    'Port_Scans'
    'Layer_2_Attacks'
)
n_elements="${#subdirectories[@]}"

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
    echo -e "                                                     |____|               \t\t ${cyan}V.1.0.0"
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

function error_distribution() {
    echo -e "${red}\n [+] ERROR, your linux distribution is not compatible with this tool, this tool works on Debian-based distributions!${default}"
    sleep 10
}

function create() {
    if [[ ! -d $directory ]];
    then
	mkdir $directory
	for (( i=0;i<=$n_elements;i++ ));
	do
	    mkdir $directory/"${subdirectories[$i]}"
	done
    fi
}

#checking required tools
function tool_check() {

    required_tools=(
        'tshark'
        'wget'
        'curl'
	'jq'
	'netcat'
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

            sudo apt-get install -fy $tool &>/dev/null

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

#load pcap files
function load_pcap() {

    clear
    banner
    echo -e "\n\n ${yellow}[MENU] \n\n${green} [1] Back \n${default}"
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
		#pendiente verificar esta parte, para verificar si es un pcap externo o generados por el programa
                while [ -f $directory/capture-$id_file.pcap ];
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
    echo -e "\n\n ${yellow}[MENU] \n\n${green} [1] Denial of Service\n\n [2] Web Attacks \n\n [3] Brute Force\n\n [4] DNS Tunneling\n\n [5] LAN Attacks\n\n [6] Back \n\n ${default}"
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

    create
    flag=0
    clear
    banner
    tool_check
    echo -e "\n\n ${yellow}[MENU] \n\n${green} [1] Attack detection\n\n [2] Reconnaissance detection\n\n [3] Threat Intelligence\n\n [4] Exit\n\n ${default}"
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
if [ $(grep -i "debian" /etc/*-release) ];
then
    clear
    main_menu
else
    error_distribution
    main_menu_option_4
fi

