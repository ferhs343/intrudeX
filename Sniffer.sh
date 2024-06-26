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

source Colors.sh
source Messages.sh
source Files.sh
source Protocols.sh
source Errors.sh

ipv4=0
ipv6=0
layer2=1
layer7=1
incoming=1
outgoing=1
hunt=1
log=1

interfaces_list=$(ifconfig | awk '{print $1}' | grep ':' | tr -d ':')
interfaces=()

arg=$1
arg2=$3
arg3=$4
arg4=$5
arg5=$6
arg6=$7
pid_sniffer=""

function show_help() {

    echo -e "${yellow}\n TTP Tracker V 1.0.0 - By: Luis Herrera :)${green}"
    echo -e "\n Usage in layer 7: ./ttptracker.sh [INTERFACE] [NET_LAYER_OPTIONS] [IP_OPTIONS] [ANALYZE_OPTIONS] [RUN_MODE_OPTIONS]"
    echo -e "\n Usage in layer 2: ./ttptracker.sh [INTERFACE] [NET_LAYER_OPTIONS] [RUN_MODE_OPTIONS]"
    echo -e "\n\t -h, --help: Show this panel."
    echo -e "\n\t -l, --list-interfaces: Show available interfaces in your system."
    echo -e "\n\t -i, --interface: Establish a listening interface."
    echo -e "\n\t ${yellow}[NET LAYER OPTIONS] ${green}"
    echo -e "\n\t -l7, --layer7: Work in layer 7."
    echo -e "\n\t -l2, --layer2: Work in layer 2."
    echo -e "\n\t ${yellow}[IP OPTIONS] ${green}"
    echo -e "\n\t -6, --ipv6: Use IPv6 protocol."
    echo -e "\n\t -4, --ipv4: Use IPv4 protocol."
    echo -e "\n\t ${yellow}[ANALYZE OPTIONS] ${green}"
    echo -e "\n\t -in, --inbound: Incoming traffic."
    echo -e "\n\t -out, --outbound: Outgoing traffic."
    echo -e "\n\t -bid, --bidirectional: Incoming and outgoing traffic."
    echo -e "\n\t ${yellow}[RUN MODE OPTIONS] ${green}"
    echo -e "\n\t -hunt, --only-hunt: Only hunt threats."
    echo -e "\n\t -logs, --only-logs: Only generate traffic logs."
    echo -e "\n\t -all, --run-all: Generate traffic logs and hunt threats.\n${default}"
}

function killer() {

    echo -e "\n Process disrupted, exiting.... "
    kill $pid_sniffer
    rm -f $procesing_logs
    rm -f $general_capture

    if [ $(ls "$logs_dir/$logs_in_process/" | grep 'trim' | wc -l) -gt 0 ];
    then
        rm -f trim*
    fi

    sleep 3
    exit
}

function builder_filter() {

    if [ "$layer7" -eq 0 ];
    then
        i=0
        default_filter="ether host ${your_mac} or host ${your_ip}"
        n_hosts="$(cat ${host_filter} | wc -l)"

        #Variables needed to exclude host traffic in whitelist
        init_keyword=""
        final_keyword=""
        wl_hosts=()

        if [ "${n_hosts}" -gt 0 ];
        then
            init_keyword="and not("
            final_keyword=")"

            for wl_host in $(cat $host_filter);
            do
                if [ "$i" -lt 1 ];
                then
                    builder="host ${wl_host}"
                else
                    builder="or host ${wl_host}"
                fi

                wl_hosts+=($builder)
                i=$((i+1))
            done
        fi
        new_filter="${default_filter} ${init_keyword} ${wl_hosts[*]} ${final_keyword}"

    elif [ "$layer2" -eq 0 ];
    then
        new_filter="not tcp and not udp"
    fi
}

function sniffer() {

    touch $general_capture
    gzip $general_capture
    general_capture="${general_capture}.gz"
    tshark -w "${general_capture}" -i $net_interface -f "${new_filter}" > /dev/null 2>&1 &
    pid_sniffer=$!
    #principal sniffer process ID
}

function port_scanner() {

    tcp_ports=()
    udp_ports=()

    if [ "$ipv4" -eq 1 ];
    then
        loopback="127.0.0.1"
    else
        loopback="::1"
    fi

    for (( i=0;i<=65535;i++ ));
    do
        nc -zv $loopback $i 2> /dev/null
        if [ "$?" -eq 0 ];
        then
            tcp_ports+=($i)
        fi
    done

    for (( i=0;i<=65535;i++ ));
    do
        nc -zvu $loopback $i 2> /dev/null
        if [ "$?" -eq 0 ];
        then
            udp_ports+=($i)
        fi
    done
}

function export_stream_pcap() {

    if [ "$mechanism_one" -eq 1 ];
    then
        tshark -r "${general_capture}" -Y \
               "${stream_filter} >= ${stream_init} && ${stream_filter} <= ${stream_fin}" \
               -w "${stream_capture}" 2> /dev/null
    else
        if [ "$partial_session" -eq 0 ];
        then
            tshark -r "${general_capture}" -Y \
                   "${stream_filter} eq ${streams[$i]}" \
                   -w "${stream_capture}" 2> /dev/null
        else
            tshark -r "${general_capture}" -Y \
                   "${stream_filter} eq ${partials[$i]}" \
                   -w "${stream_capture}" 2> /dev/null
        fi
    fi
}

function layer7() {

    partials=()
    alternate=0
    streams_filter_tcp="tcp.stream >= 0"
    streams_filter_udp="udp.stream >= 0"

    #List of TCP protocolss where TTP Tracker performs threat hunting in l7 option
    tcp_list=(
        'http'          #INCOMING/OUTGOING MODE
        'ssl'           #INCOMING/OUTGOING MODE
        'ssh'           #INCOMING/OUTGOING MODE
        'ftp'           #INCOMING/OUTGOING MODE
        'smb2'          #ONLY OUTGOING MODE
        'dcerpc'        #ONLY OUTGOING MODE
        'ntlm'          #ONLY OUTGOING MODE
        'kerberos'      #ONLY OUTGOING MODE
        'smtp'          #INCOMING/OUTGOING MODE
        'llmnr'         #ONLY OUTGOING MODE
    )

    #List of UDP protocolss where TTP Tracker performs threat hunting in l7 option
    udp_list=(
        'llmnr'
        'dcerpc'
        'kerberos'
        'tftp'          #INCOMING/OUTGOING MODE
        'dns'           #INCOMING/OUTGOING MODE
        'dhcp'          #ONLY OUTGOING MODE
        'dhcpv6'        #ONLY OUTGOING MODE
    )

    auxiliar_list=(
        'icmp'          #INCOMING/OUTGOING MODE
        'icmpv6'        #INCOMING/OUTGOING MODE
    )

    while true;
    do
        tcp_streams=()
        udp_streams=()
        streams=()
        mechanism_one=0
        partial_session=0

        if [ "$((alternate % 2))" -eq 0 ];
        then
            tcp=1
            udp=0
            stream_filter="tcp.stream"
            session=$(tshark -r "${general_capture}" \
                             -Y "${streams_filter_tcp}" \
                             -T fields -e "${stream_filter}" \
                             2> /dev/null | sort -n -u)
            tcp_streams=($session)
            streams=("${tcp_streams[@]}")

        else
            udp=1
            tcp=0
            stream_filter="udp.stream"
            session=$(tshark -r "${general_capture}" \
                             -Y "${streams_filter_udp}" \
                             -T fields -e "${stream_filter}" \
                             2> /dev/null | sort -n -u)
            udp_streams=($session)
            streams=("${udp_streams[@]}")
        fi

        if [ "${#streams[@]}" -gt 0 ];
        then
            fin="${streams[-1]}"
            if [ "$tcp" -eq 1 ];
            then
                streams_filter_tcp="${stream_filter} > ${fin}"
            else
                streams_filter_udp="${stream_filter} > ${fin}"
            fi

            if [ "${#streams[@]}" -gt 5 ];
            then
                #Begin mechanism 1
                # > 5 streams per turn
                mechanism_one=1
                mechanism_one
            else
                #Begin mechanism 2
                # < 5 streams per turn
                for (( i=0;i<=${#streams[@]} - 1;i++ ));
                do
                    export_stream_pcap
                    mechanism_two
                done
            fi
        fi

        if [[ "${#partials[@]}" -gt 0 &&
              "$tcp" -eq 1 ]];
        then
            #Partial sessions
            partial_session=1
            for (( i=0;i<=${#partials[@]} - 1;i++ ));
            do
                export_stream_pcap
                mechanism_two
            done
        fi

        sleep 3
        alternate=$((alternate+1))
    done
}

function layer2() {

    #List of protocolss where TTP Tracker performs threat hunting in l2 option
    l2_list=(
        'arp'           #INCOMING/OUTGOING MODE
        'icmp'          #INCOMING/OUTGOING MODE
        'icmpv6'        #INCOMING/OUTGOING MODE
        'stp'           #ONLY OUTGOING MODE
        'cdp'           #ONLY OUTGOING MODE
        'lldp'          #ONLY OUTGOING MODE
        'hsrp'          #ONLY OUTGOING MODE
        'dtp'           #ONLY OUTGOING MODE
    )
}

function mechanism_one() {

    stream_init="${streams[0]}"
    stream_fin=$fin
    trims=()

    if [ "$tcp" -eq 1 ];
    then
        fast_tcp "$procesing_logs"
    else
        fast_udp "$procesing_logs"
    fi

    n=$(cat $procesing_logs | wc -l)
    if [ "$((n))" -lt 500 ];
    then
        file=$procesing_logs
        if [ "$tcp" -eq 1 ];
        then
            tcp_extract_info
        else
            udp_extract_info
        fi
    else

        split $procesing_logs -l 500 trim
        mv trim* $logs_dir/$logs_in_process
        extract_trims="$(ls $logs_dir/$logs_in_process/trim*)"
        trims=($extract_trims)

        for (( i=0;i<=${#trims[@]} - 1;i++ ));
        do
            file="${trims[$i]}"
            if [ "$tcp" -eq 1 ];
            then
                tcp_extract_info
            else
                udp_extract_info
            fi
        done

        rm $logs_dir/$logs_in_process/trim*
        mechanism_one=0
    fi
}

function mechanism_two() {

    continue=0
    if [ "$partial_session" -eq 1 ];
    then
        stream="${partials[$i]}"
        continue=1
    else
        stream="${streams[$i]}"
        src_ip=$(tshark -r "${stream_capture}" \
                    -T fields -e "${ip_filter}.src" \
                    2> /dev/null | head -n 1)

        src_mac=$(tshark -r "${stream_capture}" \
                     -T fields -e "eth.src" \
                     2> /dev/null | head -n 1)

        if [[ (("$src_ip" == "${your_ip}" ||
                "$src_mac" == "${your_mac}") && "$outgoing" -eq 0) ||
              (("$src_ip" != "${your_ip}" ||
                "$src_mac" != "${your_mac}") && "$incoming" -eq 0) ]];
        then
            continue=1
        fi
    fi

    if [ "$continue" -eq 1 ];
    then
        timestamp=$(tshark -r "${stream_capture}" \
                       -T fields -e "frame.time" \
                       2> /dev/null | head -n 1 | tr ' ' '-')
        if [ "$tcp" -eq 1 ];
        then
            tcp_extract_info
        else
            udp_extract_info
        fi
    fi
}

function used_service() {

    service_list=("$@")
    for (( k=0;k<=${#service_list[@]} - 1;k++ ));
    do
        n_service=$(tshark -r "${stream_capture}" \
                           -Y "${service_list[$k]}" \
                           2> /dev/null | wc -l)
       if [ "$((n_service))" -gt 0 ];
       then
           service="${service_list[$k]}"
           if  [ "$tcp" -eq 1 ];
           then
               tcp_services_log
           else
               udp_services_log
           fi
        fi
    done
}

function preparing_log() {

    log_data=("$@")
    log="[${stream}] [${timestamp}]"

    for (( m=0;m<=${#log_data[@]} - 1;m++ ));
    do
        log+=" [${log_data[$m]}]"
    done
}

function print_log() {

    echo "${log}" >> $1
}

function validate_tcp_flags() {

    flags_history=""
    #TCP Flags
    Syn=0
    Ack=0
    Push=0
    Fin=0
    Reset=0
    Urg=0
    Null=0
    Syn_ack=0
    Push_ack=0
    Fin_ack=0
    Reset_ack=0

    for (( k=0;k<=${#flags[@]} - 1;k++ ));
    do
        if [ "${flags[$k]}" == "02" ];
        then
            Syn=1
            flags_history+="Syn "
        fi

        if [ "${flags[$k]}" == "12" ];
        then
            Syn_ack=1
            flags_history+="Synack "
        fi

        if [ "${flags[$k]}" == "10" ];
        then
            Ack=1
            flags_history+="Ack "
        fi

        if [ "${flags[$k]}" == "08" ];
        then
            Push=1
            flags_history+="Psh "
        fi

        if [ "${flags[$k]}" == "18" ];
        then
            Push_ack=1
            flags_history+="Pshack "
        fi

        if [ "${flags[$k]}" == "01" ];
        then
            Fin=1
            flags_history+="Fin "
        fi

        if [ "${flags[$k]}" == "11" ];
        then
            Fin_ack=1
            flags_history+="Finack "
        fi

        if [ "${flags[$k]}" == "04" ];
        then
            Reset=1
            flags_history+="Rst "
        fi

        if [ "${flags[$k]}" == "14" ];
        then
            Reset_ack=1
            flags_history+="Rstack "
        fi

        if [ "${flags[$k]}" == "00" ];
        then
            Null=1
            flags_history+="NULL "
        fi
    done
}

function reassembling_streams() {

    continue
}

function tcp_extract_info() {

    path_log="./$logs_dir/${logs[0]}"

    if [ "$mechanism_one" -eq 1 ];
    then
        streams_trim=()
        extract_streams="$(cat $file | awk '{print $1}' | sort -n -u)"
        streams_trim=($extract_streams)

        for (( j=0;j<=${#streams_trim[@]} - 1;j++ ));
        do
            stream="${streams_trim[$j]}"
            src_ip=$(awk -F'\t' -v stream=$stream '$1 == stream {print $4}' $file | head -n 1)
            src_mac=$(awk -F'\t' -v stream=$stream '$1 == stream {print $3}' $file | head -n 1)
            if [[ (("$src_ip" == "${your_ip}" ||
                    "$src_mac" == "${your_mac}") && "$outgoing" -eq 0) ||
                  (("$src_ip" != "${your_ip}" ||
                    "$src_mac" != "${your_mac}") && "$incoming" -eq 0) ]];
            then
                flags=()
        #       reassembling_streams
                timestamp=$(awk -F'\t' -v stream=$stream '$1 == stream {print $2}' $file | head -n 1 | tr ' ' '-')
                extract_flags=$(cat $file | awk "\$1 == \"$stream\" {print \$NF}" | sort -u | awk '{print substr($0,length($0)-1)}')
                flags=($extract_flags)
                validate_tcp_flags
                tcp_conn_status

                awk -F'\t' \
                    -v src="$src_ip" \
                    -v stream="$stream" \
                    -v flags_h="$flags_history" \
                    -v ts="$timestamp" '$1 == stream && $4 == src \
                    {print "["$1"] " "["ts"] " "["$3"] " "["$4"] " "["$5"] " "["$6"] " "["$7"] " "["$8"] " "["flags_h"]"}' \
                    $file | sort -u >> $path_log
                flags_history=""
            fi
        done
    else
        finished=0
        extract_flags=$(tshark -r "${stream_capture}" \
                               -T fields -e "tcp.flags" \
                               2> /dev/null | sort -u | awk '{print substr($0,length($0)-1)}')
        flags=($extract_flags)
        validate_tcp_flags
        tcp

        if [ "$partial_session" -eq 0 ];
        then
            data=(
                "$src_mac"
                "$src_ip"
                "$src_port"
                "$dst_mac"
                "$dst_ip"
                "$dst_port"
                "$flags_history"
            )
            preparing_log "${data[@]}"
            print_log "$path_log"
        fi

        tcp_conn_status

        if [ "$finished" -eq 1 ];
        then
            if [ "$partial_session" -eq 1 ];
            then
                timestamp=$(tshark -r "${stream_capture}" \
                                   -T fields -e "frame.time" \
                                   2> /dev/null | tail -n 1 | tr ' ' '-');
                data=(
                    "$src_mac"
                    "$src_ip"
                    "$src_port"
                    "$dst_mac"
                    "$dst_ip"
                    "$dst_port"
                    "$flags_history"
                )
                preparing_log "${data[@]}"
                print_log "$path_log"
            fi

            used_service "${tcp_list[@]}"
        fi
    fi
}

function tcp_conn_status() {

    # Case 1 ==> Conenction not finished.
    if [[ ("$Syn" -eq 1 && "$Syn_ack" -eq 1 && "$Ack" -eq 1) &&
          ("$Fin_ack" -eq 0 && "$Reset_ack" -eq 0) ]];
    then
        if [ "$partial_session" -eq 0 ];
        then
            partials+=($stream)
        fi
    fi

    # Case 2 ==> Connection finished.
    if [[ ("$Syn" -eq 1 && "$Syn_ack" -eq 1 && "$Ack" -eq 1) &&
          ("$Fin_ack" -eq 1 || "$Reset_ack" -eq 1) ]];
    then
        finished=1
        if [ "$partial_session" -eq 1 ];
        then
            for (( k=0;k<=${#partials[@]} - 1;k++ ));
            do
                if [ "$stream" == "${partials[$k]}" ];
                then
                    unset "partials[$k]"
                    break
                fi
            done
        fi
    fi
}

function udp_extract_info() {

    path_log="./$logs_dir/${logs[1]}"

    if [ "$mechanism_one" -eq 1 ];
    then
        streams_trim=()
        extract_streams="$(cat $file | awk '{print $1}' | sort -n -u)"
        streams_trim=($extract_streams)

        for (( j=0;j<=${#streams_trim[@]} - 1;j++ ));
        do
            stream="${streams[$j]}"
            src_ip=$(awk -F'\t' -v stream=$stream '$1 == stream {print $4}' $file | head -n 1)
            src_mac=$(awk -F'\t' -v stream=$stream '$1 == stream {print $3}' $file | head -n 1)
            if [[ (("$src_ip" == "${your_ip}" ||
                    "$src_mac" == "${your_mac}") && "$outgoing" -eq 0) ||
                  (("$src_ip" != "${your_ip}" ||
                    "$src_mac" != "${your_mac}") && "$incoming" -eq 0) ]];
            then
                timestamp=$(awk -F'\t' -v stream=$stream '$1 == stream {print $2}' $file | head -n 1 | tr ' ' '-')
                awk -F'\t' \
                    -v src="$src_ip" \
                    -v stream="$stream" \
                    -v ts="$timestamp" -v msg="$U1" '$1 == stream && $4 == src \
                    {print "["$1"] " "["ts"] " "["$3"] " "["$4"] " "["$5"] " "["$6"] " "["$7"] " "["$8"] " "["msg"]"}' \
                    $file | sort -u >> $path_log
            fi
        done
    else
        udp
        data=(
            "$src_mac"
            "$src_ip"
            "$src_port"
            "$dst_mac"
            "$dst_ip"
            "$dst_port"
            "$U1"
        )

        preparing_log "${data[@]}"
        print_log "$path_log"
        used_service "${udp_list[@]}"
    fi
}

function udp_services_log() {

    if [ "$service" == "dns" ];
    then
        path_log="./$logs_dir/${logs[8]}"
        dns
        query=($query)
        r_a=($r_a)
        r_aaaa=($r_aaaa)
        r_txt=($r_txt)
        c_name=($c_name)

        for (( l=0;l<=${#query[@]} - 1;l++ ));
        do
            data=(
                "${query[$l]}"
                "${r_a[$l]}"
                "${r_aaaa[$l]}"
                "${r_txt[$l]}"
                "${c_name[$l]}"
            )
            preparing_log "${data[@]}"
            print_log "$path_log"
        done
    fi
}

function tcp_services_log() {

    if [ "$service" == "http" ];
    then
        path_log="./$logs_dir/${logs[2]}"
        http
        uri=($uri)
        method=($method)
        hostname=($hostname)
        user_agent=($user_agent)
        mime_type_rq=($mime_type_rq)
        mime_type_rp=($mime_type_rp)
        status_code=($status_code)

        for (( l=0;l<=${#uri[@]} - 1;l++ ));
        do
            data=(
                "${method[$l]}"
                "${uri[$l]}"
                "${hostname[$l]}"
                "${user_agent[$l]}"
                "${mime_type_rq[$l]}"
                "${mime_type_rp[$l]}"
                "${status_code[$l]}"
            )
            preparing_log "${data[@]}"
            print_log "$path_log"
        done

    elif [ "$service" == "ssl" ];
    then
        path_log="./$logs_dir/${logs[2]}"
    fi
}

if grep -qE 'Debian|CentOS' /etc/*-release;
then
    if [ "$(id -u)" == "0" ];
    then
        logs=()
        if [ "$arg" == "--help" ] ||
           [ "$arg" == "-h" ]
        then
            show_help
            exit

        elif  [ "$arg" == "--list-interfaces" ] ||
              [ "$arg" == "-l" ]
        then
            interfaces=($interfaces_list)
            echo -e "${yellow}\n Interfaces:\n"
            for (( i=0;i<=${#interfaces[@]} - 1;i++ ));
            do
                echo -e "${green} [+] ${interfaces[$i]}${default} \n"
            done

        elif [ "$arg" == "--interface" ] ||
             [ "$arg" == "-i" ]
        then
            start_l7=0
            start_l2=0
            interface=0
            net_interface=$2
            interfaces=($interfaces_list)

            for (( i=0;i<=${#interfaces[@]} - 1;i++ ));
            do
                if [ "$net_interface" != "${interfaces[$i]}" ];
                then
                    interface=$((interface+1))
                else
                    break
                fi
            done

            if [ "$interface" -lt "$(( ${#interfaces[@]} - 1 ))" ];
            then
                start_l7=$((start_l7+1))
                start_l2=$((start_l2+1))
                your_mac=$(ifconfig $net_interface | grep 'ether' | awk '{print $2}')
            fi

            if [ "$arg2" == "--layer7" ] ||
               [ "$arg2" == "-l7" ]
            then
                start_l7=$((start_l7+1))
                layer7=0

                if [ "$arg3" == "-6" ] ||
                   [ "$arg3" == "--ipv6" ]
                then
                    start_l7=$((start_l7+1))
                    ipv6=1
                    your_ip=$(ifconfig $net_interface | grep -w 'inet6' | awk '{print $2}')
                    host_filter=$host_filter_6
                    ip_filter="ipv6"

                elif [ "$arg3" == "-4" ] ||
                     [ "$arg3" == "--ipv4" ]
                then
                    start_l7=$((start_l7+1))
                    ipv4=1
                    your_ip=$(ifconfig $net_interface | grep -w 'inet' | awk '{print $2}')
                    host_filter=$host_filter_4
                    ip_filter="ip"
                fi

                if [ "$arg4" == "--incoming" ] ||
                   [ "$arg4" == "-in" ]
                then
                    start_l7=$((start_l7+1))
                    logs=("${in_logs[@]}")
                    incoming=0

                elif [ "$arg4" == "--outgoing" ] ||
                     [ "$arg4" == "-out" ];
                then
                    start_l7=$((start_l7+1))
                    logs=("${out_logs[@]}")
                    outgoing=0

                elif [ "$arg4" == "--bidirectional" ] ||
                     [ "$arg4" == "-bid" ];
                then
                    start_l7=$((start_l7+1))
                    logs=("${out_logs[@]}")
                    outgoing=0
                    incoming=0
                fi

                if [ "$arg5" == "--only-hunt" ] ||
                   [ "$arg5" == "-hunt" ];
                then
                    start_l7=$((start_l7+1))
                    hunt=0

                elif [ "$arg5" == "--only-logs" ] ||
                     [ "$arg5" == "-logs" ];
                then
                    start_l7=$((start_l7+1))
                    log=0

                elif [ "$arg5" == "--run-all" ] ||
                     [ "$arg5" == "-all" ];
                then
                    start_l7=$((start_l7+1))
                    hunt=0
                    log=0
                fi

                if [[ "$start_l7" -eq 5 &&
                      "$arg6" == "" ]];
                then
                    echo -e "${green}\n [+] Loading, wait a moment....${default}"

                    if [ "$incoming" -eq 0 ];
                    then
                        sleep 1
                #       port_scanner
                    fi

                    for (( i=0;i<="$(( ${#logs[@]} - 1 ))";i++ ));
                    do
                        if [[ ! -f "./$logs_dir/${logs[$i]}" ]];
                        then
                            touch "./$logs_dir/${logs[$i]}"
                        fi
                    done

                    trap killer SIGINT
                    clear
                    builder_filter
                    sniffer
                    echo -e "${green}\n [+] I'm Hunting....${default}"
                    layer7
                else
                    error_args
                    sleep 2
                    show_help
                fi

            elif [ "$arg2" == "--layer2" ] ||
                 [ "$arg2" == "-l2" ]
            then
                start_l2=$((start_l2+1))
                layer2=0
                if [[ "$start_l2" -eq 2 &&
                      "$arg3" == "" ]];
                then
                    builder_filter
                    sniffer
                    echo -e "${green}\n [+] I'm Hunting....${default}"
                    layer2
                else
                    error_args
                    sleep 2
                    show_help
                fi
            fi

        else
            show_help
            exit
        fi
    else
        error_root
        sleep 5
    fi
else
    error_distribution
    sleep 5
fi
