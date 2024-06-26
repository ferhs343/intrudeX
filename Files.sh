#!/bin/bash

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

pcaps_dir="PCAPS"
logs_dir="LOGS"
logs_in_process=".logs_in_process"
procesing_logs="./$logs_dir/$logs_in_process/.logs_in_process.log"
host_filter_4="host_filter4.txt"
host_filter_6="host_filter6.txt"
general_capture=".general.pcap"
stream_capture=".stream.pcap"

out_logs=(
    'tcp.log'
    'udp.log'
    'http.log'
    'ssl.log'
    'ssh.log'
    'ftp.log'
    'smtp.log'
    'tftp.log'
    'dns.log'
    'smb2.log'
    'dcerpc.log'
    'ntlm.log'
    'kerberos.log'
    'llmnr.log'
    'dhcp.log'
    'dhcpv6.log'
)

in_logs=(
    'tcp.log'
    'udp.log'
    'http.log'
    'ssl.log'
    'ftp.log'
    'smtp.log'
    'tftp.log'
    'dns.log'
)

subdirectories=(
    'Denial_of_Service'
    'Web_Attacks'
    'Brute_Force'
    'DNS_Tunneling'
    'Layer_2_Attacks'
)
