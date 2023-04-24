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

function repeat() {

        repeat="-"
        value=25
        for ((i=0;i<=$value;i++))
        do
                echo -n "$repeat"
        done
}

function banner() {

	echo -e "${cyanColour}"
	echo -e '  ________  ______   ______             _____  __________   ________'
	echo -e ' /   ____/ /  __  \ /  ____\   _____   /     \ \_____    \ /   ____/'
	echo -e ' \____   \ |  ____/ \  \____   |____|    ---     |    ___/ \____   \'
	echo -e " /_______/ \_____>   \______\          \_____/   |    |    /_______/    ${greenColour}By: Luis Herrera :)${cyanColour}"
	echo -e "                                                 |____|                 ${greenColour}V.1.0 ${endColour}"
}

#main menu
function main_menu() {

	flag=0
	clear
	banner
	echo -e "\n${purpleColour} $(repeat)\n  SECTIONS\n $(repeat) \n\n ${redColour}[1] Red Team Tools\n\n [2] Blue Team Tools\n\n [3] Exit\n\n ${endColour}"
	echo -e "${yellowColour} Please, enter a option${endColour}\n"

	while [ "$flag" -eq 0 ];
	do
		echo -e "${greenColour}┌─[${redColour}${HOSTNAME}${greenColour}]──[${redColour}~${greenColour}]─[${yellowColour}${PWD}${greenColour}]:"
		read -p "└─────► $(tput setaf 7)" option

		if [ "$option" -eq  1 ];
	      	then
                	option_1_main_menu
			flag=1

        	elif [ "$option" -eq 2 ];
        	then
                	option_2_main_menu
			flag=1

        	elif [ "$option" -eq 3 ];
        	then
			flag=1
               	 	echo -e "Exiting.....\n"
                	sleep 1
               		exit
		else
			echo "$error"
			flag=0
		fi
	done
}

#submenu of main_menu if user select option 1
function option_1_main_menu() {

	clear
	banner
	echo -e "\n${purpleColour} $(repeat)\n  RED TEAM SECTION\n $(repeat) \n\n ${redColour}[1] Network Scanning\n\n [2] Sniffing\n\n [3] Network Attacks\n\n [4] Back\n\n ${endColour}"
	echo -e "${yellowColour} Please, enter a suboption${endColour}\n"

	while [ "$flag" -eq 0 ];
        do
                echo -e "${greenColour}┌─[${redColour}${HOSTNAME}${greenColour}]──[${redColour}~${greenColour}]─[${yellowColour}${PWD}${greenColour}]:"
                read -p "└─────► $(tput setaf 7)" suboption

                if [ "$suboption" -eq  1 ];
                then
                        suboption_1_redteam
                        flag=1

                elif [ "$suboption" -eq 2 ];
                then
                        suboption_2_redteam
                        flag=1

		elif [ "$suboption" -eq 3 ];
		then
			suboption_3_redteam
			flag=1

                elif [ "$suboption" -eq 4 ];
                then
                        flag=1
                        main_menu
                else
                        echo "$error"
                        flag=0
                fi
        done
}

#submenu of main_menu if user select option 2
function option_2_main_menu() {

        clear
        banner
        echo -e "\n${purpleColour} $(repeat)\n  BLUE TEAM SECTION\n $(repeat) \n\n ${redColour}[1] Malicious IP\n\n [2] PCAP Analyze\n\n [3] File analyze\n\n [4] Zeek\n\n [5] Back\n\n${endColour}"
        echo -e "${yellowColour} Please, enter a suboption${endColour}\n"

        while [ "$flag" -eq 0 ];
        do
                echo -e "${greenColour}┌─[${redColour}${HOSTNAME}${greenColour}]──[${redColour}~${greenColour}]─[${yellowColour}${PWD}${greenColour}]:"
                read -p "└─────► $(tput setaf 7)" suboption

                if [ "$suboption" -eq  1 ];
                then
                        suboption_1_blueteam
                        flag=1

                elif [ "$suboption" -eq 2 ];
                then
                        suboption_2_blueteam
                        flag=1

                elif [ "$suboption" -eq 3 ];
                then
                        suboption_3_blueteam
                        flag=1

		elif [ "$suboption" -eq 4 ];
		then
			suboption_4_blueteam
			flag=1

                elif [ "$suboption" -eq 5 ];
                then
                        flag=1
                        main_menu
                else
                        echo "$error"
                        flag=0
                fi
        done
}

#main program
main_menu
