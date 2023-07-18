#!/bin/bash

#All alerts to be executed in case of detecting anomalies in the network

tcp_connection_alert="[WARNING] ! ==> TCP Connection Established"
tcp_DoS_alert="[WARNING] ! ==> Possible TCP Denial Of Service Attack"
udp_DoS_alert="[WARNING] ! ==> Possible UDP Denial Of Service Attack"
banner_grabing_alert="[WARNING] ! ==> Nmap Banner Grabing Detected"
OS_detection_alert="[WARNING] ! ==> Nmap OS Recognition Detected"
brute_force_alert="[WARNING] ! ==> Brute Force Attack Detected"
zone_transfer_alert="[WARNING] ! ==> DNS Zone Transfer Deteced"
inverse_query_alert="[WARNING] ! ==> DNS Inverse Query Detected"
vlan_hopping_alert="[WARNING] ! ==> Vlan Hopping Attack Detected"
arp_poisoning_alert="[WARNING] ! ==> ARP Poisoning Attack Detected"
stp_manipulation_alert="[WARNING] ! ==> STP Manipulation Detected"
mac_flooding_alert="[WARNING] ! ==> MAC Flooding Attack Detected"
nse_scripting_alert="[WARNING] ! ==> Nmap NSE Detected"
sql_injection_alert="[WARNING] ! ==> Possible SQL Injection Detected"
