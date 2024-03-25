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

function http() {

    method=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.request.method" 2> /dev/null | tr -d '\n')
    uri=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.request.uri" 2> /dev/null | tr -d '\n')
    hostname=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.host" 2> /dev/null | tr -d '\n')
    user_agent=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.user_agent" 2> /dev/null | tr -d '\n')
    mime_type=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.content_type" 2> /dev/null | tr -d '\n')
    status_code=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.response.code" 2> /dev/null | tr -d '\n')
}

function dns() {

    query=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && ${2}" -T fields -e "dns.qry.name" 2> /dev/null | tr -d '\n')
    r_type=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && ${2} && dns.qry.name == ${query}" -T fields -e "dns.resp.type" 2> /dev/null | tr -d '\n') 
    r_name=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && ${2} && dns.qry.name == ${query}" -T fields -e "dns.resp.name" 2> /dev/null | tr -d '\n')
    r_a=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && ${2} && dns.qry.name == ${query}" -T fields -e "dns.a" 2> /dev/null | tr -d '\n')
    r_aaaa=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && ${2} && dns.qry.name == ${query}" -T fields -e "dns.aaaa" 2> /dev/null | tr -d '\n')
    r_txt=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && ${2} && dns.qry.name == ${query}" -T fields -e "dns.txt" 2> /dev/null | tr -d '\n')
}
