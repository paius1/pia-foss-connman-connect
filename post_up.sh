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

  # need AUTOCONNECT
    eval "$(awk '/AUTOCONNECT/ && !/^[:blank:]*#/{print $0}' .env 2>/dev/null)"

  # post_up.sh is kind of a misnomer
    if [[ ! "${CONNMAN_CONNECT}" =~ ^[t|T] ]] \
         &&
       [[ "${AUTOCONNECT:-false}" =~ ^[f|F] ]] #
  # both systemd and the user don't want to connect
    then echo 'AUTOCONNECT='"${AUTOCONNECT}"' CONNMAN_CONNECT='"${CONNMAN_CONNECT}"'' |
         tee >( _logger ) >( _is_not_tty && _pia_notify 6000 'pia_off_48x48.png' ) >/dev/null
           sleep 6
         _print_connection_instructions
         exit 0
    fi

    if [[ "${PRE_UP_RUN}" != 'true' ]]
    then >&2 _logger "Finishing up ..."; fi

  # by moving out of connect_to_w...sh we lost $SERVICE and $REGION_NAME
  # _is_tty then cli might be set (exported by connect_to_w....sh)
    cli="${cli:-}"
  # from ~/.config/wireguard/pia${cli}.config #
    eval "$(grep -e '^[[:blank:]]*[[:alpha:]]' ~/.config/wireguard/pia${cli}.config |  sed 's/\./_/g;s/ = \(.*\)$/="\1"/g')" #
    REGION_NAME="$( awk -F[][] '{print $2}' <<< "${Name}")"
    SERVICE="vpn_$(sed 's/\./_/g' <<< "${Host}")_${Domain}"

  # Connect with connmanctl
    if connmanctl connect "${SERVICE}"
  # SUCCESS
    then
         if _is_tty
       # running interactively #
         then echo
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

    if [[ "${PIA_DNS:-true}" == "true" ]]
  # Check and reset nameservers set by connmanctl #
    then
         if [[ "$(awk '/nameserver / {print $NF; exit}' /run/connman/resolv.conf)" != "${DNS:-10.0.0.243}" ]] #
       # connman subordinates vpn dns to any preset nameservers #
         then _logger "Replacing Connman's DNS with PIA's DNS" #
            # replace headers and first nameserver with $DNS to temporary file
              sed -i -r "s/Connection Manager/PIA-WIREGUARD/;0,/nameserver/{s/([0-9]{1,3}\.){3}[0-9]{1,3}/${DNS:-10.0.0.243}/}" \
                     /run/connman/resolv.conf #
              echo #
         fi #
       # https://gist.github.com/Tugzrida/6fe83682157ead89875a76d065874973
         #DNS_SERVER="$(./dnsleaktest.py | awk -F"by" ' /by/{print $2; exit}')"
         #_pia_notify 'DNS server is '"${DNS_SERVER}"' ' 10000; sleep 9
    fi #

  # moved from connect_to_wireguard.sh thus losing all the variables
    eval "$(awk -F'/' '{print $1}' /opt/etc/piavpn-manual/port_forward.cmd )"

  # This section did exit the script if PIA_PF is not set to "true".
  # the command for port forwarding will be sent to /tmp/port_forward.log
    if [[ $PIA_PF != "true" ]]
  # print instructions for starting port forwarding later
    then echo -e "    To enable port forwarding run\n"
         echo -e "    PIA_TOKEN=$PIA_TOKEN PF_GATEWAY=$WG_SERVER_IP PF_HOSTNAME=$WG_HOSTNAME $(pwd)/port_forwarding.sh" #| tee /tmp/port_forward.log
         echo
         echo -e "    The location used must be port forwarding enabled, or this will fail."
         echo -e "\tCall PIA_PF=true $(pwd)/get_region for a filtered list."
         echo -e "      and"
         echo -e "    port_forwading.sh must be left running to maintain the port"
         echo -e "\tIt WILL TIE UP A CONSOLE unless run in the background"
         echo
         #exit 0
    else
  # Start port_forward.sh
         echo "          logging port_forwarding.sh to /tmp/port_forward.log" #

       # allow rest of post_up.sh to run
         (sleep 2
          chmod +x /opt/etc/piavpn-manual/port_forward.cmd
          eval /opt/etc/piavpn-manual/port_forward"${cli}".cmd > /tmp/port_forward.log
         )&
         disown
    fi #

  # Iptables-restore vpn killswitch #
#########################################################
# Note to self:                                         #
# Check /storage/.config/autostart.sh for any conflicts #
#########################################################
    up="$(</proc/uptime)"
    if [[ "${up%%.*}" -lt 60 ]]
  # SYSTEM START, wait and load ip_tables module
    then _logger "taking 3"
         sleep 3
         if ! lsmod |
              grep -q '^ip_tables'
       # ip_tables module not loaded yet Don't know when it normally is
         then _logger "ip_tables module not loaded"
              modprobe ip_tables
              sleep 1
         fi
         lsmod |
         grep -q '^ip_tables' \
            && _logger "ip_tables module loaded"
    fi

    echo "Setting up firewall"
#    eval "$(awk '/WG_FIREWALL/ && !/^[:blank:]*#/{print $0}' .env 2>/dev/null)"
    iptables-restore < "${WG_FIREWALL:-rules-wireguard.v4}"

  # Add any applications to start after this

exit 0
