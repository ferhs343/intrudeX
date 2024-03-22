#!/bin/bash

pcaps_dir="PCAPS"
logs_dir="LOGS"

out_logs=(
    'sessions.log'
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
    'sessions.log'
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

general_capture=".general.pcap"
whitelist_file_4="./whitelist4.txt"
whitelist_file_6="./whitelist6.txt"
