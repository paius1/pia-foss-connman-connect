#!/opt/bin/bash
#    v 0.0.1
#    SCRIPTNAME  called by systemctl stop pia-wireguard.service
#                or by System.Exec in Favourites
#        
#        disconnects wireguard vpn
#        restores the firewall, nameservers, routing table, and stops port_forwarding.sh
#        
#        add any vpn sensitive applications e.g. stop transmission
#        at the end
#        
####
# c plgroves @ 2022

    _Usage() {
         sed >&2 -n "1d; /^###/q; /^#/!q; s/^#*//; s/^ //; 
                     s/SCRIPTNAME/${BASH_SOURCE##*/}/; p" \
                    "${BASH_SOURCE%/*}/${BASH_SOURCE##*/}"
         exit 1; }
    [[ "$1" =~ ^[-hH] ]] && _Usage "$@"

  # PIA's scripts are set to a relative path
    cd "${0%/*}" || exit 255

    export PATH=/opt/bin:/opt/sbin:"${PATH}" #

  # add kodi GUI.Notifications with timeouts and images
  #     _pia_notify 'message' 'display time' 'image file' #
  # and logging function
  #     _logger 'message' [ logfile ]
    [[ -z "${kodi_user}" ]] \
      && source ./kodi_assets/functions #

# DEBUGGING
#LOG="${LOG:-/tmp/pia-wireguard.log}"
#_logger "Starting $(pwd)/${BASH_SOURCE##*/}"
#exec > >(tee -a $LOG) #2>&1

  # How was this script called [systemd|favourites|interactively] #
  # systemd: continue #
  # favourites: pia-wireguard.service exist? #
  #             YES: stop service #
  #             NO: set logfile and continue #
  # interactively: set PRE_UP_RUN to cli #
  # 
    if _is_unset PRE_UP_RUN \
         &&
       _is_not_tty \
         &&
       [[ "$(systemctl list-unit-files pia-wireguard.service | wc -l)" -gt 3 ]]
    then
  # not called by systemd or interactively, and systemd service exists #
       # notify systemd and log to pia-wireguard log
         systemd-cat -t pia-wireguard.favourites -p notice < \
                    <( echo "Stopping pia-wireguard.service from outside of systemd" |&
                       tee -i >(_logger >/dev/null))
                       
                       # 'Called outside of systemd. Service is '" $(systemctl is-active  pia-wireguard.service)"''

         systemctl stop pia-wireguard.service &
         disown
       # calls this script with PRE_UP_RUN set
         exit 0
    elif _is_not_tty
    then LOG='/tmp/pia-wireguard.log'
  # non-interactively w/o systemd service

    elif _is_tty \
           &&
         [[ "$( wc -l < <(systemctl list-unit-files pia-wireguard.service))" -gt 3 ]]
    then
  # running interactively with systemd service
         case "$(systemctl --quiet is-active  pia-wireguard.service; echo $?)"
         in
          # systemd service active
            0|true)  systemd-cat -t pia-wireguard.cmdline -p notice < \
                                <(echo "Stopping pia-wireguard.service from the command line" |&
                                  tee -i (_logger >/dev/null))

                     systemctl stop pia-wireguard.service &
                     disown
                   # recalls this script with PRE_UP_RUN set
                     exit 0
                ;;
            *|false) PRE_UP_RUN='cli'
          # carry on
                ;;
         esac
    else
  # no systemd service
         LOG='/tmp/pia-wireguard.log'
    fi
    
  # disconnect vpn_
  # 1st connected service, is it a vpn?
    readarray -t services < <(connmanctl services)
    [[ "${services[0]}" =~ (vpn_.*)$ ]]
    if [[ -n "${wg_0:=${BASH_REMATCH[1]}}" ]]
    then _logger "$(connmanctl disconnect "${wg_0}")"
  # vpn active

         wg_0_file="$(grep -l --exclude='~$' "${wg_0##*_}" ~/.config/wireguard/*.config 2>/dev/null)"
         [[ "$(<"${wg_0_file}")" =~ Name.*\[(.*)\] ]]
         REGION="${BASH_REMATCH[1]:-}"

       # GUI notification
         _is_not_tty \
           && _pia_notify 'Disconnected from '"${REGION}"' ' 5000 "pia_off_48x48.png"

       # reset pia.config age
         touch "${wg_0_file}"

    else _logger "No current vpn connection"
  # NO
    fi

  # OKAY now iptables, DNS, route are all mangled!?

  # Get user defined iptables rules
    eval "$(awk '/MY_FIREWALL=/ {print}' .env)"

  # restore firewall (user defined or ./openrules.v4)
    iptables-restore < "${MY_FIREWALL:=openrules.v4}" \
    || echo  "Failed to restored ${MY_FIREWALL} firewall" |
       tee >(_logger) >(_is_not_tty && _pia_notify) >/dev/null

  # can we dig it
    if ! dig +time=1 +tries=2 privateinternetaccess.com >/dev/null
    then _logger "Restoring DNS nameservers"
  # NO, restore valid nameservers

       # restore a sane DNS .cache/starting_resolv.conf is saved at startup
         if [[ -f /storage/.cache/starting_resolv.conf ]]
         then cp -v /storage/.cache/starting_resolv.conf /run/connman/resolv.conf
       # Using resolv.conf from start up
         else 
       # Get nameservers from first active non-vpn_ service

            # already have array of services  
            # get nameserver from first active non vpn_ interface
              non_vpn=("$( printf '%s\n' "${services[@]}" | grep -v 'vpn_' )")
              mapfile -d ' ' NS < <(awk -F'[=|;]' '/^Nameserver/{printf "%s", $2}' ~/.cache/connman/"${non_vpn[0]##* }"/settings)
            # or fall back to opendns
    cat <<- EOF > /run/connman/resolv.conf
    # Generated by PIA WIREGUARD
    nameserver "${NS[0]:-208.67.222.222}"
    nameserver "${NS[1]:-208.67.222.220}"
EOF

         fi
    else _logger "Can resolve hostnames"
  # YES
    fi

  # port forwarding cleanup
    pf_pids=($(pidof port_forwarding.sh))

    if [ "${#pf_pids[@]}" -ne 0 ]
    then
  # stop port forwarding 
         echo "${pf_pids[@]}" |
         xargs -d $'\n' sh -c 'for pid do kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null; done' _

       # clear the log file ?
         :> /tmp/port_forward.log
         _logger "Stopped port forwarding"
    fi

  # flush vpn from routing table?
    if [[ -n "${wg_0}" ]]
    then # could try comparing original routing table
  # PIA was connected. if disconnected from Settings>CoreELEC this will be missed
       # ip of vpn: remove prefix vpn_, suffix _${Domain}, & replace '_' > '.'
         ip_flush="$(sed 's/^vpn_//;s/_/\./g' <<< "${wg_0%_*}")"
         ip route flush "${ip_flush}" 
         _logger "Flushed vpn ${ip_flush} from routing table"
       # removed from the routing table
    fi

# add anything else such stopping applications and port forwarding

exit 0
