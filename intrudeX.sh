#!/bin/bash

# intrudeX
# --------
# Herramienta enfocada a la detección de intrusos en tu host local.
#    - Detección de ataques a nivel de capa de aplicación, así como a nivel de capa 2
#    - Detección de tecnicas de reconocimiento
#    - Así mismo, intrudeX cuenta con utilidades para la ejecución de Threat Intellingece
# Luis Herrera, Abril 2023

source Files.sh
source Colors.sh

#global variables
current=$PWD
flag=0
flag2=0
instalation=0
name_option=""
name_suboption=""
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
    ["Brute_Force"]=3
    ["DNS_tunneling"]=4
    ["Layer_2_attacks"]=5
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

    echo -e "${green}\n"
    echo -e '  ██╗███╗   ██╗████████╗██████╗ ██╗   ██╗██████╗ ███████╗██╗  ██╗  '
    echo -e '  ██║████╗  ██║╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██╔════╝╚██╗██╔╝  '   
    echo -e "  ██║██╔██╗ ██║   ██║   ██████╔╝██║   ██║██║  ██║█████╗   ╚███╔╝   ${yellow}"
    echo -e '  ██║██║╚██╗██║   ██║   ██╔══██╗██║   ██║██║  ██║██╔══╝   ██╔██╗   '
    echo -e "  ██║██║ ╚████║   ██║   ██║  ██║╚██████╔╝██████╔╝███████╗██╔╝ ██╗                            ${cyan}By: Luis Herrera${yellow}"
    echo -e "  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝                            ${cyan}V 1.0.0${red}"                       
    echo -e "${red}"
    echo -e " +-------------------------------------------------------------------------------------------------------------+"
    echo -e " | Welcome to intrudeX!!, the ideal tool to monitor the network in search of intruders. Happy hunting!! :D     |"
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
    echo -e "${red}\n ERROR, the specified PCAP file does not exist in this directory!!\n\n${default}"
}

function error_instalation() {
    echo -e "${red}\n [+] ERROR, an unexpected error occurred during installation!!${default}"
}

function error_distribution() {
    echo -e "${red}\n [+] ERROR, your linux distribution is not compatible with intrudeX, this tool works on Debian-based distributions!${default}"
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

    tool_validator=0
    no_tool=()

    for i in "${required_tools[@]}"
    do
	if [[ ! $(which $i) ]];
	then
	    tool_validator=$((validator+1))
	fi
    done

    if [ "$tool_validator" -gt 0 ];
    then
	tool_validator=0
	echo -e "${yellow}\n [+] Checking required tools.....${default}"
	sleep 1
	for i in "${required_tools[@]}"
	do
            if [[ $(which $i) ]];
            then
		echo -e "\n${green} [$i] ${red}Tool is installed $(frame .) ${green}[OK]${default}"
		sleep 1
            else
		echo -e "\n${green} [$i] ${red}Tool is installed $(frame .) [ERROR]${default}"
		no_tool+=("$i")
		sleep 1
            fi
	    n_elements="${#no_tool[@]}"
	done

        for tool in "${no_tool[@]}"
        do
	    echo -e "${yellow}\n\n [+] Installing Tool ${green}(${tool})${yellow}, wait a moment.....${default}"

	    sudo apt-get install -fy $tool &>/dev/null

	    if [ "$?" -eq 0 ];
	    then
		echo -e "${green}\n [+] Installation complete.${default}"
		tool_validator=$((tool_validator+1))
                sleep 1
	    else	
                error_instalation
                sleep 2
                main_menu_option_4
	    fi
        done

	if [ "$tool_validator" -eq "$n_elements" ];
	then
	    echo -e "${green}\n\n [+] Reloading......${default}"
	    sleep 2
	    main_menu
        fi
    else
	 echo -e "${green}\n [+] The necessary tools are installed.${default}"
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

function attack_detection_option_5() {
    load_pcap
}

function attack_detection_option_6() {
    main_menu
}

function list_files() {

    paths=(
	"./${directory}/Denial_of_Service"
	"./${directory}/Web_Attacks"
	"./${directory}/Brute_Force"
	"./${directory}/DNS_Tunneling"
	"./${directory}/Layer_2_Attacks"
    )
    count=0

    echo -e "${green} $(frame -)\n  PCAPS Saved\n $(frame -)${default}"
    
    for file in $(ls "${paths[$1-1]}")
    do
	count=$((count+1))
	echo ""
	echo -e "${purple}  [+] ${file}${default}"
    done

    if [ "$count" -lt 1 ];
    then
	echo -e "${purple}\n  [+] No files available to analyze yet.${default}"
    fi
}

#load pcap files
function load_pcap() {

    clear
    banner
    echo -e "\n ${yellow}[MENU] \n\n${green} [1] Back \n${default}"
    check=0
    subdirectory=""

    for i in "${subdirectories[@]}"
    do
	if [ "$i" == 'Denial_of_Service' ];
	then
	    if [ "$value" -eq 1 ];
	    then
		list_files 1
		subdirectory=$i
	    fi

	elif [ "$i" == 'Web_Attacks' ];
	then
	    if [ "$value" -eq 2 ];
	    then
		list_files 2
		subdirectory=$i
	    fi
	       
	elif [ "$i" == 'Brute_Force' ];
	then
	    if [ "$value" -eq 3 ];
	    then
		list_files 3
		subdirectory=$i
	    fi
		
	elif [ "$i" == 'DNS_Tunneling' ];
	then
	    if [ "$value" -eq 4 ];
	    then
		list_files 4
		subdirectory=$i
	    fi
	    
	elif [ "$i" == 'Layer_2_Attacks' ];
	then
	    if [ "$value" -eq 5 ];
	    then
		list_files 5
		subdirectory=$i
	    fi
	    
	elif [ "$value" -eq 6 ];
	then
	    list_files 6
	    subdirectory=$i
	fi
    done
       
    while [ "$check" -eq 0 ];
    do
        echo -e "\n\n${yellow} Enter the PCAP file to analyze.${default}\n"
        prompt_suboption
        read -p "└─────► $(tput setaf 7)" pcap
	
        if [ "$pcap" == "1" ];
        then
            main_menu_option_1
            check=1
        else  
            echo -e "\n${green} [+] Loading PCAP [${pcap}] .....${default}\n"
            sleep 2

            if [ -f "./$directory/$subdirectory/$pcap" ];
            then
                echo -e "\n${green} [+] Getting ready....."
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
            echo -e "\n\n${yellow} Please, if you analyze other PCAP file, enter name of this, otherwise, press 1 for back.${default}\n"
            check=0
        fi
    done
}

#option 1 in main menu
function main_menu_option_1() {

    flag=0
    clear
    banner
    echo -e "\n ${yellow}[MENU] \n\n${green} [1] Denial of Service\n\n [2] Web Attacks \n\n [3] Brute Force\n\n [4] DNS Tunneling \n\n [5] Layer 2 Attacks\n\n [6] Back \n\n ${default}"
    echo -e "${yellow} Please, enter a option${default}\n"

    while [ "$flag" -eq 0 ];
    do
        prompt_option
        read -p "└─────► $(tput setaf 7)" suboption

        if [[ "$suboption" -gt 6 || "$suboption" -lt 1 ]];
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

    echo -e "\n Exiting...\n"
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

function main() {
    
    #main program
    if [ $(grep -i "debian" /etc/*-release) ];
    then
	clear
	main_menu
    else
	error_distribution
	main_menu_option_4
    fi
}

main
