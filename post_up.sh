#!/opt/bin/bash
#    v 0.0.1, c plgroves gmail 2022
#    SCRIPTNAME called by PATH/connect_to_wireguard_with_token.sh
#        
#        put commands here to run after vpn is up
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
  # we lost $AUTOCONNECT $SERVICE, $REGION_NAME, etc.
    source .env 2>/dev/null
    AUTOCONNECT="${:-false}"
    PIA_PF="${PIA_PF:-false}"
    PIA_DNS="${PIA_DNS:-true}"

  # WG_SERVER_IP=$Host=WG_SERVER_IP WG_HOSTNAME=$Domain=PF_HOSTNAME DNS=$WireGuard_DNS
  # from ~/.config/wireguard/pia${cli}.config (cli is passed when _is_tty)
    eval "$(grep -e '^[[:blank:]]*[[:alpha:]]' ~/.config/wireguard/pia"${cli}".config |
            sed 's/\./_/g;s/ = \(.*\)$/="\1"/g')"

    mapfile -t tokenFile < /opt/etc/piavpn-manual/token
    PIA_TOKEN="${tokenFile[0]}"
    WG_SERVER_IP="${Host}"
    WG_HOSTNAME="${Domain}"

    SERVICE="vpn_${Host//./_}${Domain/#/_}"
    [[ "${Name}" =~ \[(.*)\] ]]
    REGION_NAME="${BASH_REMATCH[1]:-}"

  # post_up.sh is kind of a misnomer
    if [[ ! "${CONNMAN_CONNECT}" =~ ^[t|T] ]] \
         &&
       [[ "${AUTOCONNECT:-false}" =~ ^[f|F] ]] #
    then 
  # both systemd and the user don't want to connect
         echo 'AUTOCONNECT='"${AUTOCONNECT}"' CONNMAN_CONNECT='"${CONNMAN_CONNECT}"'' |
         tee >( _logger ) >( _is_not_tty && _pia_notify 6000 'pia_off_48x48.png' ) >/dev/null
           sleep 6

         _print_connection_instructions
         exit 0
    fi

  # message for _is_tty and pia-wireguard.log
    if [[ "${PRE_UP_RUN}" != 'true' ]]
    then >&2 _logger "Finishing up ..."; fi

  # Connect with connmanctl
    if connmanctl connect "${SERVICE}"
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
              echo 'Successfully connected to '"${REGION_NAME}"' ' |
              tee >(_logger ) >(_pia_notify 5000 'pia_on_48x48.png' ) >/dev/null #
              sleep 3 # for notification
         fi
    else
  # FAILURE
         echo 'CONNMAN failed to connect to '"${REGION_NAME}"'!' |
         tee >( _logger ) >( _is_not_tty _pia_notify 10000 'pia_off_48x48.png' ) >/dev/null
         exit 255
    fi

    if [[ "${PIA_DNS}" == "true" ]]
    then
  # Check and reset nameservers set by connmanctl
         if [[ "$(awk '/nameserver / {print $NF; exit}' /run/connman/resolv.conf)" != "${WireGuard_DNS}" ]]
         then _logger "Replacing Connman's DNS with PIA's DNS"
       # connman subordinates vpn dns to any preset nameservers
            # replace headers and first nameserver with $DNS to temporary file
              sed -i -r "s/Connection Manager/PIA-WIREGUARD/;0,/nameserver/{s/([0-9]{1,3}\.){3}[0-9]{1,3}/${WireGuard_DNS:-10.0.0.243}/}" \
              /run/connman/resolv.conf
              echo
         fi
       # https://gist.github.com/Tugzrida/6fe83682157ead89875a76d065874973
         #DNS_SERVER="$(./dnsleaktest.py | awk -F"by" ' /by/{print $2; exit}')"
         #_pia_notify 'DNS server is '"${DNS_SERVER}"' ' 10000; sleep 9
    fi #

  # the command for port forwarding was saved in /opt/etc/piavpn-manual/port_forward[-(user_added)].cmd
    if [[ $PIA_PF != "true" ]]
    then
  # print instructions for starting port forwarding later
         echo -e "    To enable port forwarding run\n"
         echo -e "    $(< /opt/etc/piavpn-manual/port_forward.cmd )"
         echo
         echo -e "    The location used must be port forwarding enabled, or this will fail."
         echo -e "\tCall PIA_PF=true $(pwd)/get_region for a filtered list."
         echo -e "      and"
         echo -e "    port_forwading.sh must be left running to maintain the port"
         echo -e "\tIt WILL TIE UP A CONSOLE unless run in the background"
         echo
    else
  # Start port_forward.sh
         echo "        logging port_forwarding.sh to /tmp/port_forward.log" #

       # allow rest of post_up.sh to run
         (sleep 2
          chmod +x /opt/etc/piavpn-manual/port_forward"${cli}".cmd
          eval /opt/etc/piavpn-manual/port_forward"${cli}".cmd > /tmp/port_forward.log
         )&
         disown
    fi #

#########################################################
# Note to self:                                         #
# Check /storage/.config/autostart.sh for any conflicts #
#########################################################
    up="$(</proc/uptime)"
    if [[ "${up%%.*}" -lt 60 ]]
    then _logger "taking 3"
  # SYSTEM START, wait and load ip_tables module
         #sleep 3

         if [[ ! "$(lsmod)" =~ ip_tables[[:blank:]] ]]
         then _logger "ip_tables module not loaded"
       # ip_tables module not loaded yet Don't know when it normally is
              modprobe ip_tables
              sleep 1
         fi

         [[ "$(lsmod)" =~ ip_tables[[:blank:]] ]] \
           && _logger "ip_tables module loaded"
    fi

  # Iptables-restore vpn killswitch #
    echo "Setting up firewall"
    iptables-restore < "${WG_FIREWALL:-rules-wireguard.v4}"

  # add any applications to start after this

exit 0
