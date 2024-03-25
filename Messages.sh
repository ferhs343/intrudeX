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

#TCP/UDP Messages

T1="TCP Connection started"
T2="TCP SYN request, no reply"
T3="TCP Connection rejected, possible port scan"
T4="TCP Connection finished"
U1="UDP Session started"

#HTTP Messages

H1="Suspicous file download over HTTP!!"
H2="Possible HTTP endpoint discovery!!"
H3="HTTP File download with different MIME_TYPE!!"
H4="HTTP unicode-host detected!!"
H5="Malicious HTTP hostname detected!!"
H6="SQL Commands in HTTP URI!!"
H6="Possible XSS attack!!"
H7="Possible path traversal attack!!"
H8="Possible webshell attack!!"
H9="Multiple HTTP 400 codes!!"
H10="HTTP Microsoft BITS detected!!"
H11="Anomalous HTTP body lenght!!"

#DNS Messages

D1="Malicious domain detected!!"
D2="Possible DNS tunneling!!"
D3="Suspicious DNS TXT answers!!"
D4="DNS Query detected!!"

#FTP Messages

F1="FTP Multiple login incorrect!!"
F2="FTP Login succefull!!"
F3="FTP DELETE Command detected!!"
F4="FTP GET Command detected!!"
F5="FTP PUT Command detected!!"

#SMTP Messages

S1="Suspicious mail address detected!!"
S2="Suspicious file adjunted over SMTP!!"

#TFTP Messages

#SSH Messages

SS1="SSH Multiple login incorrect!!"
SS2="SSH Login succefull!!"

#ICMP Messages

I1="ICMP Echo request!!"
I2="Posible ICMP tunneling!!"

#DHCPv4 Messages

DH1="Possible DHCP starvation!!"
DH2="DHCP discover request!!"

#SMB2 Messages

SM1="SMB Read request to suspicious file!!"
SM2="SMB Multiple connections to admin file share!!"
SM3="SMB Read request to malicious file!!"
SM4="SMB Write request in admin file share!!"

#KERBEROS Messages

K1="Possible kerberos password spraying!!"
K2="Possible kerberos bruteforce!!"

#NTLM Messages

#LLMNR Messages

#DCE_RPC Messages

#SSL Messages

#STP Messages

#ARP Messages

#DTP Messages

#ICMPv6 Messages

#DHCPv6 Messages

