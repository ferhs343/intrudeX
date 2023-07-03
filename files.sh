#!/bin/bash

directory="PCAPS"
subdirectories=(
    'External_Pcaps'
    'Denial_of_Service'
    'Port_Scans'
    'Layer_2_Attacks'
)
general_capture=".general.pcap"
id=1
file="DoS-${id}.pcap"
