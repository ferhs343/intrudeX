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

    uri=$(tshark -r "${general_capture}" -Y "tcp.stream eq ${1} && http.request" -T fields -e "http.request.uri" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    method=$(tshark -r "${general_capture}" -Y "tcp.stream eq ${1} && http.request" -T fields -e "http.request.method" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    hostname=$(tshark -r "${general_capture}" -Y "tcp.stream eq ${1} && http.request" -T fields -e "http.host" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    user_agent=$(tshark -r "${general_capture}" -Y "tcp.stream eq ${1} && http.request" -T fields -e "http.user_agent" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    mime_type_rq=$(tshark -r "${general_capture}" -Y "tcp.stream eq ${1} && http.request" -T fields -e "http.content_type" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    mime_type_rp=$(tshark -r "${general_capture}" -Y "tcp.stream eq ${1} && http.response" -T fields -e "http.content_type" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    status_code=$(tshark -r "${general_capture}" -Y "tcp.stream eq ${1} && http.response" -T fields -e "http.response.code" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
}

function dns() {

    query=$(tshark -r "${general_capture}" -Y "udp.stream eq ${1} && dns.flags == 0x0100" -T fields -e "dns.qry.name" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    r_a=$(tshark -r "${general_capture}" -Y "udp.stream eq ${1} && dns.flags == 0x8100" -T fields -e "dns.a" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    r_aaaa=$(tshark -r "${general_capture}" -Y "udp.stream eq ${1} && dns.flags == 0x8100" -T fields -e "dns.aaaa" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    r_txt=$(tshark -r "${general_capture}" -Y "udp.stream eq ${1} && dns.flags == 0x8100" -T fields -e "dns.txt" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    c_name=$(tshark -r "${general_capture}" -Y "udp.stream eq ${1} && dns.flags == 0x8100" -T fields -e "dns.cname" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
}
