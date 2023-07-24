#!/bin/bash

directory="PCAPS"
subdirectories=(
    'Denial_of_Service'
    'Web_Attacks'
    'Brute_Force'
    'DNS_Tunneling'
    'Layer_2_Attacks'
)
general_capture=".general.pcap"
id_pcap=0
file="capture-${id_pcap}.pcap"
