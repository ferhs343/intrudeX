#!/bin/bash

# intrudeX
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

function error_option() {
    echo -e "${red}\n ERROR, the specified option does not exist.\n\n${default}"
}

function error_load_pcap() {
    echo -e "${red}\n ERROR, the specified PCAP file does not exist in this directory.\n\n${default}"
}

function error_instalation() {
    echo -e "${red}\n [+] ERROR, an unexpected error occurred during installation.${default}"
}

function error_distribution() {
    echo -e "${red}\n [+] ERROR, your linux distribution is not compatible with intrudeX, this tool works on Debian-based distributions.${default}"
}

function error_args() {
    echo -e "${red}\n ERROR, one or more invalid arguments. ${default}"
}

function error_root() {
    echo -e "${red}\n ERROR, to run TTPTracker you must be root. ${default}\n"
}
