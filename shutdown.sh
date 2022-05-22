#!/opt/bin/bash
#    v 0.9.0, c plgroves gmail 2022
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
       [[  $(systemctl list-unit-files pia-wireguard.service) =~ able ]] #
    then
  # not called by systemd or interactively, and systemd service exists #

         systemd-cat -t pia-wireguard.favourites -p notice < \
                    <( echo "Stopping pia-wireguard.service from outside of systemd" |&
       # notify systemd and log to pia-wireguard log
                       tee -i >(_logger) >/dev/null)

         systemctl stop pia-wireguard.service &
         disown
       # calls this script with PRE_UP_RUN set
         exit 0

    elif _is_not_tty
    then LOG='/tmp/pia-wireguard.log'
  # non-interactively w/o systemd service

    elif _is_tty \
           &&
         [[  $(systemctl list-unit-files pia-wireguard.service) =~ able ]] #
    then
  # running interactively with systemd service
         case $(_service_is_active pia-wireguard)
         in
          # systemd service active
            0|true)  systemd-cat -t pia-wireguard.cmdline -p notice < \
                                <(echo "Stopping pia-wireguard.service from the command line" |
                     # notify systemd and log to $LOG
                                  tee -i >(_logger) >/dev/null)

                     systemctl stop pia-wireguard.service &
                   # recalls this script with PRE_UP_RUN set
                     disown
                     exit 0
                ;;
            *|false) export PRE_UP_RUN='cli'
          # carry on
                ;;
         esac
    else
  # no systemd service
         LOG='/tmp/pia-wireguard.log'
    fi

  # disconnect vpn_
    readarray -t services < <(connmanctl services)

  # 1st connected service, is vpn?
    if [[ "${services[0]}" =~ (vpn_.*)$ ]]
    then connmanctl disconnect "${BASH_REMATCH[1]}" |&
  # YES
         tee >( sleep 0.1; _logger) >/dev/null

         wg_0="${BASH_REMATCH[1]}"
         readarray -t wg_0_file < <(grep -l --exclude='~$' "${wg_0##*_}" /storage/.config/wireguard/*.config 2>/dev/null)
       # reset pia.config age
         touch "${wg_0_file[*]}" 2>/dev/null

         if _is_not_tty
         then
       # GUI notification

            # pia filename containing wg0's region name
              [[ "$(<"${wg_0_file[-1]}")" =~ Name.*\[(.*)\] ]]

              _pia_notify 'Disconnected from '"${BASH_REMATCH[1]:-vpn}"' ' 5000 "pia_off_48x48.png"
         fi

    else _logger "No current vpn connection"
  # NO
    fi

  # OKAY now iptables, DNS, route are all mangled!?

  # Check for user defined iptables rules
    nl=$'\n'
    match='MY_FIREWALL='
    while read -r line
    do if [[ "${line}" =~ .*${match}[^${nl}]* ]]
       then eval "${BASH_REMATCH[0]}"
            _is_set "${MY_FIREWALL}" \
              && break
       fi
    done < .env

  # restore firewall (user defined or ./openrules.v4)
    iptables-restore < "${MY_FIREWALL:=openrules.v4}" \
      || echo  "Failed to restored ${MY_FIREWALL} firewall" |&
         tee >(_logger) >(_is_not_tty && _pia_notify) >/dev/null

  # can we dig it
    if ! dig +time=1 +tries=2 privateinternetaccess.com >/dev/null
    then _logger "Restoring DNS nameservers"
  # NO, restore valid nameservers

         if [[ -f /storage/.cache/starting_resolv.conf ]]
         then cp -v /storage/.cache/starting_resolv.conf /run/connman/resolv.conf
       # use resolv.conf from start up

         else 
       # check nameservers from first active non-vpn_ service

            # already have array of services  
              while read -r line # 1000x 4.72s
              do [[ ! "${line}" =~ .*vpn_ ]] \
                   && non_vpn+=("$line")
              done < <( printf '%s\n' "${services[@]}")

            # get nameserver from first active non vpn_ interface settings
              nl=$'\n'
              mapfile -t settings< /storage/.cache/connman/"${non_vpn[0]##* }"/settings
              [[ ${settings[*]} =~ .*Nameservers=([^$nl]*)\;+ ]]
              settings[0]="${BASH_REMATCH[1]%%;*}"
              settings[1]="${BASH_REMATCH[1]#*;}"
            # or fall back to opendns

    cat <<-EOF > /run/connman/resolv.conf
    # Generated by PIA WIREGUARD
    search $(</proc/sys/kernel/domainname)
    nameserver "${settings[0]:-208.67.222.222}"
    nameserver "${settings[1]:-208.67.222.220}"
	EOF

         fi

    else _logger "Can resolve hostnames"
  # YES
    fi

  # port forwarding cleanup
    pf_pids=($(pidof port_forwarding.sh))

    if [[ "${#pf_pids[@]}" -ne 0 ]]
    then
  # stop port forwarding 
         echo "${pf_pids[@]}" |
         xargs -d $'\n' sh -c 'for pid do kill -9 -$pid 2>/dev/null; wait $pid 2>/dev/null; done' _

       # clear the log file ?
         :> /tmp/port_forward.log
         _logger "Stopped port forwarding"
    fi

  # flush vpn from routing table?
    if _is_set "${wg_0}"
    then
  # PIA was connected.
  # if disconnected from Settings>CoreELEC this will be missed, but doesn't seem to cause problems

       # ip of vpn: remove prefix vpn_, suffix _${Domain}, & replace '_' > '.'
         s3d="${wg_0#*_}"
         s3d2="${s3d%_*}"
         ip_flush="${s3d2//_/.}"

       # remove from the routing table
         ip route flush "${ip_flush}" \
           && _logger "Flushed vpn ${ip_flush} from routing table"
    fi

# add anything else such stopping applications and port forwarding

exit 0
