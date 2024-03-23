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

    method=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.request.method" 2> /dev/null)
    uri=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.request.uri" 2> /dev/null)
    user_agent=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.user_agent" 2> /dev/null)
    mime_type=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.content_type" 2> /dev/null)
    status_code=$(tshark -r "${general_capture}" -Y "tcp.port == ${1}" -T fields -e "http.response.code" 2> /dev/null)
}

function dns() {

    query=$(tshark -r "${general_capture}" -Y "udp.port == ${1}" -T fields -e "dns.qry.name" 2> /dev/null)
    response_t=$(tshark -r "${general_capture}" -Y "udp.port == ${1}" -T fields -e "dns.resp.type" 2> /dev/null)
    response_n=$(tshark -r "${general_capture}" -Y "udp.port == ${1}" -T fields -e "dns.resp.name" 2> /dev/null)
}
