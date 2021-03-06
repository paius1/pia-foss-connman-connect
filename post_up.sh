#!/opt/bin/bash
#    v 0.9.0, c plgroves gmail 2022
#    SCRIPTNAME called by systemd ExecStartPost
#               or PATH/connect_to_wireguard_with_token.sh,
#               when run from favourites or tty
#        
#        SCRIPTNAME is misleading as this actually bring the tunnel up
#                   allowing for reuse of valid pia.config files
#        1st check autoconnect|connman_connect
#        setup DNS
#        start up port_forwarding
#        append commands here to run after vpn is up
#        
#         e.g. transmission
#        
####
# 

    _Usage() {
         sed >&2 -n "1d; /^###/q; /^#/!q; s/^#*//; s/^ //; 
                     s!PATH!$(pwd)!; s/SCRIPTNAME/${BASH_SOURCE##*/}/; p" \
                    "${BASH_SOURCE%/*}/${BASH_SOURCE##*/}"
         exit 1; }
    [[ "$1" =~ ^[-hH] ]] && _Usage "$@"

  # PIA's scripts are set to a relative path #
    cd "${0%/*}" || exit 1 #

    export PATH=/opt/bin:/opt/sbin:"${PATH}" #

    [[ -z "${kodi_user}" ]] \
      && source ./kodi_assets/functions

# DEBUGGING
#LOG="${LOG:-/tmp/pia-wireguard.log}"
#_logger "Starting $(pwd)/${BASH_SOURCE##*/}"
#exec > >(tee -a $LOG) #2>&1

  # by moving actual connection out of connect_to_w...sh
  # and allowing reuse of pia.config < 24 hrs old
  # we lose $AUTOCONNECT etal, $SERVICE, $REGION_NAME, etc.

    function check_vars() {
        local var_names=("$@")
        local nl var_name
        declare -a env

        mapfile -t env < .env
        nl=$'\n'

        echo -n "SET "
            for var_name in "${var_names[@]}"
            do if _is_empty "${!var_name}"
               then eval "$([[ $(printf '%s\n' "${env[@]}") =~ ([^${nl}]*${var_name}=[^${nl}]*) ]] && echo "${BASH_REMATCH[1]}")"
                    if _is_set "${!var_name}"
                    then echo -n "$var_name=${!var_name} "
                    fi
               fi
            done
        echo "from .env file"
 }

  # variables set in normal run_setup.sh call
  # if unset check .env file
    check_vars AUTOCONNECT PIA_PF PIA_DNS WG_FIREWALL

  # or set to defaults
    AUTOCONNECT="${AUTOCONNECT:-false}"
    PIA_PF="${PIA_PF:-false}"
    PIA_DNS="${PIA_DNS:-true}"

  # variables set in normal connect_to_w...sh call
  # from /storage/.config/wireguard/pia${cli}.config ($cli is passed when _is_tty)
    declare Host Domain Name WireGuard_DNS
    eval "$(grep -e '^[[:blank:]]*[[:alpha:]]' ~/.config/wireguard/pia"${cli}".config |
            sed 's/\./_/;s/ = \(.*\)$/="\1"/g')"
          # replace dots with _'s for variable names, spills over to dot.URL

    SERVICE="vpn_${Host//./_}${Domain/#/_}"
    [[ "${Name}" =~ \[(.*)\] ]]
    REGION_NAME="${BASH_REMATCH[1]:-}"
    WireGuard_DNS="${WireGuard_DNS//_/.}"

  # post_up.sh is kind of a misnomer
    shopt -s nocasematch
    if [[ "${CONNMAN_CONNECT}" != *"t"* ]] \
         &&
       [[ "${AUTOCONNECT:-false}" == *"f"* ]] #
    then 
  # both systemd and the user don't want to connect
         echo 'AUTOCONNECT='"${AUTOCONNECT}"' CONNMAN_CONNECT='"${CONNMAN_CONNECT}"'' |
         tee >( _logger ) >( _is_not_tty && _pia_notify 6000 'pia_off_48x48.png' ) >/dev/null
           _is_not_tty \
             && sleep 6

       # recreate inline variables from connect_to_w...sh for function
         read -r PIA_TOKEN</opt/etc/piavpn-manual/token; WG_SERVER_IP="${Host//_/.}" WG_HOSTNAME="${Domain}" \
         _print_connection_instructions
         exit 0
    fi

  # message for _is_tty and pia-wireguard.log
    if [[ "${PRE_UP_RUN}" != *"t"* ]]
    then >&2 _logger "Finishing up ..."; fi

    shopt -u nocasematch

# PIA currently does not support IPv6. In order to be sure your VPN
# connection does not leak, it is best to disabled IPv6 altogether.
# IPv6 can also be disabled via kernel commandline param, so we must
# first check if this is the case.
    if [[ -f /proc/net/if_inet6 ]] \
         &&
       [[ $(sysctl -n net.ipv6.conf.all.disable_ipv6) -ne 1 ||
          $(sysctl -n net.ipv6.conf.default.disable_ipv6) -ne 1 ]]
    then sysctl -w net.ipv6.conf.all.disable_ipv6=1
         sysctl -w net.ipv6.conf.default.disable_ipv6=1
    fi

  # Connect with connmanctl
       readarray -t services < <(connmanctl services)
       [[ "${services[0]}" =~ (vpn_.*)$ ]]
    until [[ -n "${wg_0:=${BASH_REMATCH[1]}}" ]]
    do connmanctl connect "${SERVICE}" 2>/dev/null
       ((n++)) 
       echo "connection tries = ${n}"
       [[ "${n}" -ge 5 ]] && break
       sleep 0.3
       readarray -t services < <(connmanctl services)
       [[ "${services[0]}" =~ (vpn_.*)$ ]]
done

    if [[ "${n}" -lt 5 ]]
    then
  # SUCCESS
         if _is_tty
         then echo
       # running interactively #
              echo "    The WireGuard interface was created."
              echo "    At this point, internet should work via WIREGUARD VPN."
              echo 
              echo "    To disconnect the VPN, run:"
              echo 
              echo "    $(pwd)/shutdown.sh"
              echo 
         else
       # or not #
              echo 'Connected to '"${REGION_NAME}"' ' |
              tee >(_logger ) >(_pia_notify 5000 'pia_on_48x48.png' ) >/dev/null #
#              sleep 3 # for notification
         fi
    else
  # FAILURE
         echo 'CONNMAN failed to connect to '"${REGION_NAME}"'!' |
         tee >( _logger ) >( _is_not_tty && _pia_notify 10000 'pia_off_48x48.png' ) >/dev/null
         exit "${n}"
    fi

    shopt -s nocasematch
    if [[ "${PIA_DNS}" == *"t"* ]]
    then
  # Check and reset nameservers set by connmanctl
         mapfile -t resolv_conf < /run/connman/resolv.conf
         [[ "${resolv_conf[*]}" =~ nameserver[[:blank:]]*(([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}) ]]
         if [[ "${BASH_REMATCH[1]}" != "${WireGuard_DNS}" ]]
         then _logger "Replacing Connman's DNS with PIA's DNS"
       # connman subordinates vpn dns to any preset nameservers
            # replace headers and first nameserver with $DNS to temporary file
              sed -i -r "s|Connection Manager|PIA-WIREGUARD|;
                         s|search[[:blank:]]*.*|search ${Domain}|;
                         0,/nameserver/{s/([0-9]{1,3}\.){3}[0-9]{1,3}/${WireGuard_DNS:-10.0.0.243}/}" \
              /run/connman/resolv.conf
              echo
         fi

  # Optional DNS check
       # https://gist.github.com/Tugzrida/6fe83682157ead89875a76d065874973
         #read -r -d. up < /proc/uptime
         #if [[ "${up}" -gt 120 ]]
         #then DNS_SERVER=("$(_parse_JSON 'city' < <(./dnsleaktest.py -j ) | head -1)")
              #echo  "DNS server is in ${DNS_SERVER[0]}" |
              #tee >(_logger) >(_is_not_tty && _pia_notify) >/dev/null
              #sleep 3
         #fi
    fi

  # request port for forwarding
    if [[ $PIA_PF != *"t"* ]]
    then
  # No, print instructions for starting port forwarding later
         echo -e "    To enable port forwarding run\n"
         read -r PIA_TOKEN</opt/etc/piavpn-manual/token #
         echo -e " PIA_TOKEN=${PIA_TOKEN} PF_GATEWAY=${Host//_/.} PF_HOSTNAME=${Domain}  \\"
         echo -e " $(pwd)/port_forwarding.sh"
         echo
         echo -e "    The location used must be port forwarding enabled, or this will fail."
         echo -e "\tCall PIA_PF=true $(pwd)/get_region for a filtered list."
         echo -e "      and"
         echo -e "    port_forwading.sh must be left running to maintain the port"
         echo -e "\tIt WILL TIE UP A CONSOLE unless run in the background"
         echo
    else
  # Yes, start port_forward.sh

       # get tokenFile
             check_vars  PIA_USER PIA_PASS
             PIA_USER="${PIA_USER}" PIA_PASS="${PIA_PASS}" "$(pwd)"/get_token.sh \
               && mapfile -t tokenFile < /opt/etc/piavpn-manual/token
         #fi

         if _is_set "${tokenFile[0]}"
         then echo "    logging port_forwarding to /tmp/port_forward.log" |&
       # have token, proceed with ./port_forwarding.sh
              tee >(_logger) >/dev/null

            # allow post_up.sh to continue

                _logger " PIA_TOKEN=${tokenFile[0]} PF_GATEWAY=${Host//_/.} PF_HOSTNAME=${Domain} $(pwd)/port_forwarding.sh" #|&

              ( sleep 2
                PIA_TOKEN="${tokenFile[0]}" PF_GATEWAY="${Host//_/.}" PF_HOSTNAME="${Domain}" "$(pwd)"/port_forwarding.sh >> /tmp/port_forward.log 2>&1
              )>/dev/null 2>&1 & 
              disown
         else echo "Failed to find a valid token"
              PIA_PF=false
         fi
    fi #
    shopt -u nocasematch

#########################################################
# Note to self:                                         #
# Check /storage/.config/autostart.sh for any conflicts #
#########################################################
    read -r -d. up </proc/uptime
    if [[ "${up}" -lt 60 ]]
    then #_logger "taking 3"
  # SYSTEM START, wait and load ip_tables module if required
         #sleep 3

         if [[ ! "$(lsmod)" == *"ip_tables"* ]]
         then _logger "ip_tables module not loaded"
       # ip_tables module not loaded yet Don't know when it normally is
              modprobe ip_tables
              sleep 1
         fi

         [[ "$(lsmod)" == *"ip_tables"* ]] \
           && _logger "ip_tables module loaded"
    fi

  # Iptables-restore vpn killswitch #
    echo "Setting up firewall"
    iptables-restore < "${WG_FIREWALL:-rules-wireguard.v4}"

  # add any applications to start after this

exit 0
