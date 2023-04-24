#!/bin/bash

# SECUREOPS, HERRAMIENTA CON MÚLTIPLES FUNCIONALIDADES Y OPCIONES PARA AUTOMATIZAR PROCESOS
# ELABORADO POR ==> LUIS HERRERA (21 ABRIL - ABRIL 2023)
# ULTIMA MODIFICACIÓN ==> 21 ABRIL

clear

#colours
endColour="\033[0m\e[0m"
yellowColour="\e[1;93m"
redColour="\e[1;91m"
cyanColour="\e[1;94m"
greenColour="\e[1;92m"
purpleColour="\e[1;95m"

#variables
flag=0
error=$(echo -e "${redColour}\n ERROR, the specified option does not exist!..\n\n${endColour}")

function banner() {

        echo -e "${greenColour}"
        echo -e '                    /\___/\___/\___/\___/\___/\___/\___/\               '
        echo -e "${cyanColour}"
        echo -e '      ________  ______   ______             _____  __________   ________'
        echo -e '     /   ____/ /  __  \ /  ____\   _____   /     \ \_____    \ /   ____/'
        echo -e '     \____   \ |  ____/ \  \____   |____|    ---     |    ___/ \____   \ '
        echo -e "     /_______/ \_____>   \______\          \_____/   |    |    /_______/    ${redColour}By: Luis Herrera :)${cyanColour}"
        echo -e "                                                     |____|                 ${redColour}V.1.0 ${greenColour}"
        echo -e "                      ___  ___  ___  ___  ___  ___  ___"
        echo -e "                    \/   \/   \/   \/   \/   \/   \/   \/"
        echo -e "${yellowColour}\n\n Esta herramienta fue creada para detectar los principales ataques dentro de un PCAP${endColour}"
}

function pcap_analyze_option() {

        flag=0
        clear
        banner
        echo -e "\n\n${greenColour} [1] TCP SYN Flood\n\n [2] Nmap Scan \n\n [3] Vlan Hopping\n\n [4] HSRP Attack\n\n [5] TCP Port Scan\n\n [6] ARP Spoofing\n\n [7] DHCP Spoofing\n\n [8] Back \n\n ${endColour}"
        echo -e "${yellowColour} Please, enter a option${endColour}\n"

        while [ "$flag" -eq 0 ];
        do
                echo -e "${greenColour}┌─[${redColour}${HOSTNAME}${greenColour}]──[${redColour}~${greenColour}]─[${yellowColour}/MainMenu/PcapAnalyze/${greenColour}]:"
                read -p "└─────► $(tput setaf 7)" suboption

                if [ "$suboption" -eq 1 ];
                then
                        flag=1

                elif [ "$suboption" -eq 2 ];
                then
                        flag=1

                elif [ "$suboption" -eq 3 ];
                then
                        flag=1

                elif [ "$suboption" -eq 4 ];
                then
                        flag=1

                elif [ "$suboption" -eq 5 ];
                then
                        flag=1

                elif [ "$suboption" -eq 8 ];
                then
                        main_menu
                        flag=1
                else
                        echo "$error"
                        flag=0
                fi
        done
}

#main menu
function main_menu() {

        flag=0
        clear
        banner
        echo -e "\n\n${greenColour} [1] PCAP Analyze\n\n [2] Sniffing\n\n [3] Packet Manipulation\n\n [4] Layer 2 Attacks\n\n [5] Malicious Ip\n\n [6] Exit\n\n ${endColour}"
        echo -e "${yellowColour} Please, enter a option${endColour}\n"

        while [ "$flag" -eq 0 ];
        do
                echo -e "${greenColour}┌─[${redColour}${HOSTNAME}${greenColour}]──[${redColour}~${greenColour}]─[${yellowColour}/MainMenu/${greenColour}]:"
                read -p "└─────► $(tput setaf 7)" option

                if [ "$option" -eq 1 ];
                then
                        pcap_analyze_option
                        flag=1

                elif [ "$option" -eq 2 ];
                then
                        sniffing
                        flag=1

                elif [ "$option" -eq 3 ];
                then
                        packet_manipulation
                        flag=1

                elif [ "$option" -eq 4 ];
                then
                        layer_2_attacks
                        flag=1

                elif [ "$option" -eq 5 ];
                then
                        malicious_ip
                        flag=1

                elif [ "$option" -eq 6 ];
                then
                        echo -e "\nEXITING......"
                        sleep 1
                        flag=1
                        exit
                else
                        echo "$error"
                        flag=0
                fi
        done
}

#main program
main_menu
