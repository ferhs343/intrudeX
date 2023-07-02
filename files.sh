#!/bin/bash

directory="PCAPS"
subdirectories=(
    'External_Pcaps'
    'Denial_of_Service'
    'Port_Scans'
    'Layer_2_Attacks'
)
general_capture=".general.pcap"
id_DoS=1
file="DoS-${id_DoS}.pcap"
