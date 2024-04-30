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

source Files.sh

function tcp() {

    src_mac=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "eth.src" 2> /dev/null | head -n 1)
    src_ip=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "${ip_filter}.src" 2> /dev/null | head -n 1)
    src_port=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "tcp.srcport" 2> /dev/null | head -n 1)
    dst_mac=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "eth.dst" 2> /dev/null | head -n 1)
    dst_ip=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "${ip_filter}.dst" 2> /dev/null | head -n 1)
    dst_port=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "tcp.dstport" 2> /dev/null | head -n 1)
}

function fast_tcp() {

    tshark -r "${general_capture}" \
    -T fields \
    -e "tcp.stream" \
    -e "frame.time" \
    -e "eth.src" \
    -e "ip.src" \
    -e "tcp.srcport" \
    -e "eth.dst" \
    -e "ip.dst" \
    -e "tcp.dstport" \
    -e "tcp.flags" &> /dev/null > $1
}

function udp() {

    src_mac=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "eth.src" 2> /dev/null | head -n 1)
    src_ip=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "${ip_filter}.src" 2> /dev/null | head -n 1)
    src_port=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "udp.srcport" 2> /dev/null | head -n 1)
    dst_mac=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "eth.dst" 2> /dev/null | head -n 1)
    dst_ip=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "${ip_filter}.dst" 2> /dev/null | head -n 1)
    dst_port=$(tshark -r "${stream_capture}" -Y "${1}" -T fields -e "udp.dstport" 2> /dev/null | head -n 1)
}

function fast_udp() {

    tshark -r "${general_capture}" \
    -T fields \
    -e "udp.stream" \
    -e "frame.time" \
    -e "eth.src" \
    -e "ip.src" \
    -e "udp.srcport" \
    -e "eth.dst" \
    -e "ip.dst" \
    -e "udp.dstport" &> /dev/null > $1
}

function http() {

    uri=$(tshark -r "${stream_capture}" -Y "http.request" -T fields -e "http.request.uri" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    method=$(tshark -r "${stream_capture}" -Y "http.request" -T fields -e "http.request.method" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    hostname=$(tshark -r "${stream_capture}" -Y "http.request" -T fields -e "http.host" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    user_agent=$(tshark -r "${stream_capture}" -Y "http.request" -T fields -e "http.user_agent" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    mime_type_rq=$(tshark -r "${stream_capture}" -Y "http.request" -T fields -e "http.content_type" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    mime_type_rp=$(tshark -r "${stream_capture}" -Y "http.response" -T fields -e "http.content_type" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    status_code=$(tshark -r "${stream_capture}" -Y "http.response" -T fields -e "http.response.code" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
}

function dns() {

    query=$(tshark -r "${stream_capture}" -Y "dns.flags == 0x0100" -T fields -e "dns.qry.name" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    r_a=$(tshark -r "${stream_capture}" -Y "dns.flags.response == 1" -T fields -e "dns.a" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    r_aaaa=$(tshark -r "${stream_capture}" -Y "dns.flags.response == 1" -T fields -e "dns.aaaa" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    r_txt=$(tshark -r "${stream_capture}" -Y "dns.flags.response == 1" -T fields -e "dns.txt" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
    c_name=$(tshark -r "${stream_capture}" -Y "dns.flags.response == 1" -T fields -e "dns.cname" 2> /dev/null | sed 's/^$/-/g' | tr -d ' ')
}
