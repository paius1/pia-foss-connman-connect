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

    export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin #

# DEBUGGING #
# shellcheck source=/media/paul/coreelec/storage/sources/pia-wireguard/kodi_assets/functions
    [[ -z "${kodi_user}" ]] \
      && source ./kodi_assets/functions #

    if [[ "${PRE_UP_RUN+y}" != 'true' ]]
    then >&2 _logger "Finishing up ..."; fi

  # by moving out of connect_to...sh we lost $SERVICE and $REGION_NAME
    eval "$(</storage/.config/wireguard/connman.vars )"

  # Connect with connmanctl
    if connmanctl connect "${SERVICE}"
  # SUCCESS
    then
         if [[ -t 0 || -n "${SSH_TTY}" ]]
        # RUNNING INTERACTIVELY #
         then echo
              echo "    The WireGuard interface got created.
        At this point, internet should work via WIREGUARD VPN.

    To disconnect the VPN, run:

        $(pwd)/shutdown.sh
"
_pia_notify 'Successfully connected to '"${REGION_NAME}"' '
         else
              _logger 'Successfully connected to '"${REGION_NAME}"' '
              _pia_notify 'Successfully connected to '"${REGION_NAME}"' '
              ## sleep 2 # for notification #
         fi #
    else echo "CONNMAN service ${SERVICE} failed!"
  # FAILED
         [[ ! -t 0 && ! -n "${SSH_TTY}" ]] \
           && _pia_notify "    FAILED            "
         _logger "    FAILED            "
         exit 255 #
    fi #

    if [[ "${PIA_DNS:-true}" == "true" ]] #
  # Check and reset nameservers set by connmanctl #
    then DNS="${DNS:-$(awk '/WireGuard.DNS/{printf "%s", $3}'  ~/.config/wireguard/pia.config)}" #
         if [[ "$(awk '/nameserver / {print $NF; exit}' /etc/resolv.conf)" != "${DNS}" ]] #
       # connman subordinates vpn dns to any preset nameservers #
         then _logger "Replacing Connman's DNS with PIA DNS" #
            # replace headers and first nameserver with $DNS to temporary file
              sed -r "s/Connection Manager/PIA-WIREGUARD/;0,/nameserver/{s/([0-9]{1,3}\.){3}[0-9]{1,3}/${DNS}/}" \
                     /etc/resolv.conf > /tmp/resolv.conf #
            # overcome editing a file in place
              cat /tmp/resolv.conf > /etc/resolv.conf && rm /tmp/resolv.conf #
              echo #
         fi #
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
          eval /opt/etc/piavpn-manual/port_forward.cmd >> /tmp/port_forward.log 2>/dev/null
           )&
         disown
    fi #

  # Iptables-restore vpn killswitch #
#########################################################
# Note to self:                                         #
# Check /storage/.config/autostart.sh for any conflicts #
#########################################################
    if [[ "$(awk -F'.' '{print $1}' < /proc/uptime)" -lt 60 ]] #
  # SYSTEM START wait and load ip_tables module #
    then echo "taking 3" #
         if ! lsmod | grep -q '^ip_tables' #
       # ip_tables module not loaded yet Don't know when it normally is
         then echo ip_tables module not loaded #
              modprobe ip_tables #
              sleep 1 #
         fi #
         lsmod | grep -q '^ip_tables' \
         && echo -e "\nip_tables module loaded\n" #
    fi #

    echo "Setting up firewall" #
    iptables-restore < "${WG_FIREWALL:-rules-wireguard.v4}" #

  # Add any applications to start after this

exit 0
