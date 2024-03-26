#/bin/bash

# +------------------------------------------------------------------------+
# | TTP Tracker                                                            |
# | -----------                                                            |
# |                                                                        |
# | Threat hunting endpoint tool in search of TTP in the network traffic.  |
# |                                                                        |
# | Author: Luis Herrera - @Ferhs343                                       |
# | Contact: fer.hs343@gmail.com                                           |
# | V 1.0.0                                                                |
# |                                                                        |
# +------------------------------------------------------------------------+

function preparing_log() {

    log_data=("$@")
    log="[${port}] [${timestamp}]"
    
    for (( m=0;m<="$(( ${#log_data[@]} - 1 ))";m++ ));
    do
	log+=" [${log_data[$m]}]"
    done
}

function print_log() {

    echo "${log}" >> $1
}
