
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

source Print_logs.sh

function http() {

    uri=$(tshark -r "${general_capture}" -Y "tcp.port == ${1} && http.request.uri" -T fields -e "http.request.uri" 2> /dev/null)
    uri=($uri)

    for (( l=0;l<="$(( ${#uri[@]} - 1 ))";l++ ));
    do
        method=$(tshark -r "${general_capture}" -Y "tcp.port == ${1} && http.request.uri == \"${uri[$l]}\"" -T fields -e "http.request.method" 2> /dev/null)
	method+=("$method")
        hostname=$(tshark -r "${general_capture}" -Y "tcp.port == ${1} && http.request.uri == \"${uri[$l]}\"" -T fields -e "http.host" 2> /dev/null)
	hostname+=("$hostname")
        user_agent=$(tshark -r "${general_capture}" -Y "tcp.port == ${1} && http.request.uri == \"${uri[$l]}\"" -T fields -e "http.user_agent" 2> /dev/null)
	user_agent+=("$user_agent")
        mime_type=$(tshark -r "${general_capture}" -Y "tcp.port == ${1} && http.request.uri == \"${uri[$l]}\"" -T fields -e "http.content_type" 2> /dev/null)
	mime_type+=("$mime_type")
        status_code=$(tshark -r "${general_capture}" -Y "tcp.port == ${1} && http.request.uri == \"${uri[$l]}\"" -T fields -e "http.response.code" 2> /dev/null)
	status_code+=("$status_code")

	data=("${method[$l]}" "${uri[$l]}" "${hostname[$l]}" "${user_agent[$l]}" "${mime_type[$l]}" "${status_code[$l]}")
        preparing_log "${data[@]}"
	print_log "${2}"
    done
}

function dns() {

    query=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && dns.flags == 0x0100" -T fields -e "dns.qry.name" 2> /dev/null)
    query=($query)

    for (( l=0;l<="$(( ${#query[@]} - 1 ))";l++ ));
    do
       r_a=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && dns.flags == 0x8180" -T fields -e "dns.a" 2> /dev/null)
       r_aaaa=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && dns.flags == 0x8180" -T fields -e "dns.aaaa" 2> /dev/null)
       r_txt=$(tshark -r "${general_capture}" -Y "udp.port == ${1} && dns.flags == 0x8180" -T fields -e "dns.txt" 2> /dev/null)

       data=("${query[$l]}" "${r_a}" "${r_aaaa}" "${r_txt}")
       preparing_log "${data[@]}"
       print_log "${2}"
    done
}
