#!/bin/bash

# SEC-OPS, HERRAMIENTA QUE DETECTA ACTAQUES BASICOS DESDE UN ARCHIVO PCAP, ASI MISMO, AGILIZA EJECUCION DE ALGUNOS ATAQUES A REDES.
# ELABORADO POR ==> LUIS HERRERA (21 ABRIL - ABRIL 2023)
# ULTIMA MODIFICACIÓN ==> 25 ABRIL

clear

#colours
endColour="\033[0m\e[0m"
yellowColour="\e[1;93m"
redColour="\e[1;91m"
cyanColour="\e[1;94m"
greenColour="\e[1;92m"
purpleColour="\e[1;95m"

#variables
actual=$PWD
new_directory="PCAPS"
flag=0
error=$(echo -e "${redColour}\n ERROR, the specified option does not exist!..\n\n${endColour}")
error_load_pcap=$(echo -e "${redColour}\n ERROR, the specified PCAP file does not exist!..\n\n${endColour}")
flag2=0

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

#principal banner
function banner() {

        echo -e "${greenColour}"
        echo -e '      ________  ______   ______             _____  __________   ________'
        echo -e '     /   ____/ /  __  \ /  ____\   _____   /     \ \_____    \ /   ____/'
        echo -e '     \____   \ |  ____/ \  \____   |____|    ---     |    ___/ \____   \ '
        echo -e "     /_______/ \_____>   \______\          \_____/   |    |    /_______/             ${cyanColour}By: Luis Herrera :)${greenColour}"
        echo -e "                                                     |____|                          ${cyanColour}V.1.0 ${endColour} "
        echo -e "${redColour}\n -------------------------------------------------------------------------------------------------------"
        echo -e " | The ideal tool to speed up the process of detecting basic attacks from a pcap file, as streamlining |"
        echo -e " | the processes of attacks on local networks.                                                         |"
        echo -e " ------------------------------------------------------------------------------------------------------- ${endColour}"
}

function tool_check() {

        tools=(
                'tshark'
                'scapy'
                'yersinia'
        )

        tool_check=0
        no_tool=()

        echo -e "${purpleColour}\n\n [+] Checking required tools.....${endColour}"
        sleep 0.2

        for i in "${tools[@]}"
        do
                if [[ $(which $i) ]];
                then
                        echo -e "\n${redColour} [*]${greenColour} $i ${redColour} Tool is installed ........................................................ ${greenColour}[OK]"
                        sleep 0.2
                else
                        echo -e "\n${redColour} [*]${greenColour} $i ${redColour} Tool is installed ........................................................ [ERROR]"
                        tool_check=1
                        no_tool+=("$i")
                        sleep 1
                fi
        done

        if [ "$tool_check" -eq 1 ];
        then
                for tool in "${no_tool[@]}"
                do

                        echo -e "${purpleColour}\n\n [+] Installing Tool ${greenColour}${tool}${purpleColour}, wait a moment.....${endColour}"

                        sudo apt install -fy $tool &>/dev/null

                        if [ "$?" -eq 0 ];
                        then
                                echo -e "${greenColour}\n [+] Installation complete.${endColour}"
                                sleep 1
                        else
                                echo -e "${redColour}\n [+] ERROR, an unexpected error occurred during installation!!..${endColour}"
                                sleep 2
                                main_menu_option_6
                        fi
                done

                echo -e "${greenColour}\n\n [+] Reloading......${endColour}"
                sleep 2
                main_menu
        fi
}

#pcap analyzer options
function pcap_analyzer_option_1() {
        load_pcap
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
        echo " "
}

#load pcap files
function load_pcap() {

        clear
        banner
        echo -e "\n\n${greenColour} [1] Back \n${endColour}"
        echo -e "\n${yellowColour} Please, enter the path of PCAP file to analyze.${endColour}\n"
        check=0

        while [ "$check" -eq 0 ];
        do
                echo -e "${greenColour}┌─[${redColour}${HOSTNAME}${greenColour}]──[${redColour}~${greenColour}]─[${yellowColour}/MainMenu/PcapAnalyzer/${name_suboption}${greenColour}]:"
                read -p "└─────► $(tput setaf 7)" path

                if [ "$path" == "1" ];
                then
                        main_menu_option_1
                        check=1

                else
                        echo -e "\n${greenColour} [+] Find ${path} .....${endColour}\n"
                        sleep 2

                        if [ -f "$path" ];
                        then

                                i=1
                                while [ -f $actual/$new_directory/capture-$i.pcap ];
                                do
                                        i=$((i+1))
                                done

                                cp $path $actual/$new_directory/capture-$i.pcap

                                echo -e "\n${greenColour} [+] Correct! File selected ==> ${path} \n ${endColour}"
                                echo -e "\n${greenColour} [+] Analyzing PCAP..... \n ${endColour}"
                                sleep 2
                                detect_${name_suboption}

                        else
                                echo -e "$error_load_pcap"
                                check=0
                        fi
                fi

                echo -e "\n${yellowColour} Please, if you analyze other PCAP file, enter de path of this, otherwise, press 1 for back.${endColour}\n"
        done
}

#option 1 in main menu
function main_menu_option_1() {

        flag=0
        clear
        banner
        echo -e "\n\n${greenColour} [1] TCP SYN Flood\n\n [2] Nmap Scan \n\n [3] Vlan Hopping\n\n [4] HSRP Attack\n\n [5] TCP Port Scan\n\n [6] ARP Spoofing\n\n [7] DHCP Spoofing\n\n [8] Back \n\n ${endColour}"
        echo -e "${yellowColour} Please, enter a option${endColour}\n"

        while [ "$flag" -eq 0 ];
        do
                echo -e "\n${greenColour}┌─[${redColour}${HOSTNAME}${greenColour}]──[${redColour}~${greenColour}]─[${yellowColour}/MainMenu/${name_option}/${greenColour}]:"
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
                        echo ${error}
                        flag=0
                        flag2=0
                fi

        done
}

#exit
function main_menu_option_6() {

        echo -e "\nEXITING...\n"
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
        echo -e "\n\n${greenColour} [1] PCAP Analyze\n\n [2] Sniffing\n\n [3] Packet Manipulation\n\n [4] Layer 2 Attacks\n\n [5] Malicious Ip\n\n [6] Exit\n\n ${endColour}"
        echo -e "${yellowColour} Please, enter a option${endColour}\n"

        while [ "$flag" -eq 0 ];
        do
                echo -e "\n${greenColour}┌─[${redColour}${HOSTNAME}${greenColour}]──[${redColour}~${greenColour}]─[${yellowColour}/MainMenu/${greenColour}]:"
                read -p "└─────► $(tput setaf 7)" option

                if [[ "$option" -gt 7 || "$option" -lt 1 ]];
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
                        echo ${error}
                        flag=0
                        flag2=0
                fi
        done
}

#main program
main_menu
if [[ ! -d $new_directory ]];
then
        mkdir $new_directory
fi
