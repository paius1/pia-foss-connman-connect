#!/opt/bin/bash
#    v 0.0.1
#    SCRIPTNAME  called by systemctl stop pia-wireguard.service
#                  or by System.Exec in Favourites
#        
#        disconnects from wireguard vpn
#        restores the firewall, nameservers, stops port_forwarding.sh
#        
#        add any vpn sensitive applications e.g. transmission to stop
#        at the end
#        
####
# c plgroves @ 2022

  # PIA's scripts are set to a relative path
    cd "${0%/*}" || exit 255

  # running from favourites and a systemd service file exits then use systemd
    if
    [[ "$(systemctl list-unit-files pia-wireguard.service | wc -l)" -gt 3 ]] \
    && \
    [[ -z "${PRE_UP_RUN+y}" ]] \
    && \
    [[ ! -t 0 && ! -n "${SSH_TTY}" ]]
    then # systemd service exists, not called, and we are running non-interactively
         systemd-cat -t pia-wireguard.favourites -p warning <<< "Stopping service with systemd"
         systemctl stop pia-wireguard.service &
         exit 0
    fi

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

    log="${LOG:=/dev/null}"
    LOG="${1:-${log}}" # export LOG to environment to monitor these scripts
    bash_source="${#BASH_SOURCE}"; export TAB=$((bash_source+1))


  # process id's of run_setup.sh's #
    pids=($(pidof run_setup.sh)) #
    if [ "${#pids[@]}" -gt 0 ] #
  # Is run_setup.sh running
    then logger "run_setup.sh is still running, will stop"
         echo "${pids[@]}" | xargs kill -9 >/dev/null 2>&1
    fi

  # disconnect VPN
    logger 'Disconnecting from '"${REGION}"''
    wg_0="$(grep vpn_ < <( connmanctl services) | awk '{print $NF}')"
    connmanctl disconnect "${wg_0}"

  # for OSNotifications
    [ -z "${kodi_user}" ] && source ./kodi_assets/functions
    REGION="$(/opt/bin/jq -r '.name' < /tmp/regionData )"
    [[ ! -t 0 && ! -n "${SSH_TTY}" ]] \
    && _pia_notify 'Disconnected from '"${REGION}"' '

  # OKAY now iptables, DNS, route are all mangled?

  # restore firewall
  # user defined or ./openrules.v4
    logger "restoring the  firewall"
    iptables-restore < "${MY_FIREWALL:-openrules.v4}"

  # restore a sane DNS .cache/starting_resolv.conf is saved at startup
    logger "restoring DNS nameservers"
    if [ -f /storage/.cache/starting_resolv.conf ]
    then cat /storage/.cache/starting_resolv.conf > /etc/resolv.conf
    else # first active non vpn_ interface nameservers?
           iface=$(connmanctl services | awk '/^\*/ && !/vpn_/{print $NF; exit}')
         # Nameserver definition from $iface/settings
           mapfile  -d ' '  NS < <(awk -F'[=|;]' '/^Nameserver/{print $2}'  /storage/.cache/connman/${iface}/settings)
         #                      or opendns
           nameserver="${NS[0]:-208.67. 222.222}"
    cat <<- EOF > /etc/resolv.conf
    # Generated by PIA WIREGUARD
    nameserver "${nameserver}"
EOF
    fi

  # stop port forwarding 
    logger "stopping port forwarding"
    pf_pids=($(pidof port_forwarding.sh))
    if [ "${#pf_pids[@]}" -ne 0 ]
    then logger "Stopping port forwarding"
         echo "${pf_pids[@]}" | xargs kill -9 >/dev/null 2>&1
       # clear the log file
         > /tmp/port_forward.log
    fi

  # flush vpn from routing table
    logger "flushing vpn ${ip_flush} from routing table"
    ip_flush="$(sed 's/^vpn_//;s/_/\./g' <<< ${wg_0})"
    ip route flush "${ip_flush}" 

# add anything else such stopping applications and port forwarding
exit 0
