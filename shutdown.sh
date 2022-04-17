#!/opt/bin/bash
#    v 0.0.1, c plgroves gmail 2022
#    SCRIPTNAME 
#        runs after pia-wireguard service stops
#        restores the firewall TODO
#        restores nameservers
#        stops port_forwarding.sh
#        disconnects from any vpn
#        add any vpn sensitive applications e.g. transmission
#        
####
# 

  # PIA's scripts are set to a relative path
    cd "${0%/*}" || exit 255

  # get mydns, firewall?
    source .env 2>/dev/null

    _Usage() {
         sed >&2 -n "1d; /^###/q; /^#/!q; s/^#*//; s/^ //; 
                     s/SCRIPTNAME/${BASH_SOURCE##*/}/; p" \
                    "${BASH_SOURCE%/*}/${BASH_SOURCE##*/}"
         exit 1; }
    [[ "$1" =~ ^[-hH] ]] && _Usage "$@"

    function logger() {
        local message="${1}"; local source="${2:-${BASH_SOURCE}}"; local log="${3:-$LOG}"
        local tab spaces 
        tab="${TAB:-100}"
        IFS="" spaces="$(printf "%$((tab*2))s")"
        printf %s:[%s]:%.$((${tab}-${#source}))s%s%s  "$(date)" "$(cut -d- -f2- <<< "${source##*/}") " "${spaces} " "${message}" $'\n'| tee -a "${log}"
}

    log='/dev/null'
    LOG="${1:-${log}}"
    bash_source="${#BASH_SOURCE}"; export TAB=$((bash_source+1))

  # disconnect VPN
    logger "Disconnecting from Private Internet Access"
    rm /storage/.config/wireguard/pia.config 2>/dev/null

# OKAY now iptables, DNS are all mangled?

  # restore firewall
  # previously defined or saved firewall fallback ./openrules.v4
    logger "restoring the  firewall"
    if [ -z "${MY_FIREWALL}" ] && [ -f /tmp/my_firewall.v4 ]
    then MY_FIREWALL='/tmp/my_firewall.v4'
    fi
    iptables-restore < ${MY_FIREWALL:-openrules.v4}

  # restore a sane DNS
    logger "restoring sane nameservers"
    if [ -f /storage/.cache/starting_resolv.conf ]
    then cat /storage/.cache/starting_resolv.conf > /etc/resolv.conf
    else logger "no preexisting resolv.conf winging it"
cat << EOF > /etc/resolv.conf
# Generated by PIA WIREGUARD
nameserver ${mydns:-208.67. 222.222}
EOF
    fi

  # stop port forwarding 
    logger "stopping port forwarding"
    pf_pids=($(pidof port_forwarding.sh))
    if [ "${#pf_pids[@]}" -ne 0 ]
    then logger "Stopping port forwarding"
         echo "${pf_pids[@]}" | xargs kill -9 >/dev/null 2>&1
    fi
    #ps aux|grep [p]ort_forward | awk '{print $2}' | xargs kill -9 >/dev/null 2>&1

# add anything else such stopping applications and port forwarding
exit 0
