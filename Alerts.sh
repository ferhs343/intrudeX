#!/bin/bash

#All alerts to be executed in case of detecting anomalies in the network

tcp_connection_alert="[ALERT] ! ==> TCP Connection Established"
tcp_DoS_alert="[ALERT] ! ==> Possible TCP Denial Of Service Attack"
udp_DoS_alert="[ALERT] ! ==> Possible UDP Denial Of Service Attack"
banner_grabing_alert="[ALERT] ! ==> Nmap Banner Grabing Detected"
OS_detection_alert="[ALERT] ! ==> Nmap OS Recognition Detected"
brute_force_alert="[ALERT] ! ==> Brute Force Attack Detected"
zone_transfer_alert="[ALERT] ! ==> DNS Zone Transfer Deteced"
inverse_query_alert="[ALERT] ! ==> DNS Inverse Query Detected"
vlan_hopping_alert="[ALERT] ! ==> Vlan Hopping Attack Detected"
vlan_double_tagging_alert="[ALERT] ! ==> Vlan Double Tagging Detected"
arp_poisoning_alert="[ALERT] ! ==> ARP Poisoning Attack Detected"
stp_manipulation_alert="[ALERT] ! ==> STP Manipulation Detected"
mac_flooding_alert="[ALERT] ! ==> MAC Flooding Attack Detected"
