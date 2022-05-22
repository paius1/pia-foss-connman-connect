#!/opt/bin/bash
#    v 0.9.0, c plgroves gmail 2022
#    SCRIPTNAME called by ExecStartPre in service file
#              PATH/run_setup.sh
#           or PATH/connect_to_wireguard_with_token.sh,
#               when run from tty
#        
#        sets a safe and sane environment
#         e.g. disconnect vpn_XX_XX_XX_XX
#              reset firewall
#              check DNS resolution
#              stop vpn dependent applications e.g. port_forwarding, transmission
####
# 

    _Usage() {
         sed >&2 -n "1d; /^###/q; /^#/!q; s/^#*//; s/^ //; 
                     s!PATH!$(pwd)!; s/SCRIPTNAME/${BASH_SOURCE##*/}/; p" \
                    "${BASH_SOURCE%/*}/${BASH_SOURCE##*/}"
         exit 1; }
    [[ "$1" =~ ^[-hH] ]] && _Usage "$@"

  # PIA's scripts are set to a relative path
    cd "${0%/*}" || exit 255

    export PATH=/opt/bin:/opt/sbin:"${PATH}"

  # source functions
    [[ -z "${kodi_user}" ]] \
      && source ./kodi_assets/functions #

# DEBUGGING
    #export LOG="${LOG:-/tmp/pia-wireguard.log}"
    #_logger "Starting $(pwd)/${BASH_SOURCE##*/}"
    #exec > >(tee -a $LOG) #2>&1

  # CHECK FOR SYSTEM STARTUP
    read -r -d. up </proc/uptime
    if [[ "${up}" -lt 60 ]]
    then _logger "System Startup, waiting..."
  # system has just started wait, save a copy of resolv.conf and the routing table
         sleep 1
       # assume the nameservers at startup are good
         cp -v /run/connman/resolv.conf /storage/.cache/starting_resolv.conf |
         tee >(_logger) >/dev/null
       # same for the routing table
         ip route save table all > /storage/.config/ip_route_clean.bin
         _logger "ip route show all > /storage/.config/ip_route_clean.bin"
    fi

  # recommend running as a systemd service
    if _is_unset PRE_UP_RUN
    then echo "No systemd service exists" |
  # no systemd service
         tee >(_logger) >(_is_not_tty && _pia_notify) >/dev/null
         sleep 3
    fi

  # stop any vpn's connections
    readarray -t services < <(connmanctl services)

  # 1st connected service, is vpn?
    if [[ "${services[0]}" =~ (vpn_.*)$ ]]
    then connmanctl disconnect "${BASH_REMATCH[1]}" |&
  # YES, disconnect
         tee >( sleep 0.1; _logger) >/dev/null

         readarray -t wg_0_file < <(grep -l --exclude='~$' "${BASH_REMATCH[1]##*_}" /storage/.config/wireguard/*.config 2>/dev/null)
       # reset pia.config age
         touch "${wg_0_file[*]}" 2>/dev/null

         if _is_not_tty
         then
       # GUI notification

            # pia filename containing wg0's region name
              [[ "$(<"${wg_0_file[0]}")" =~ Name.*\[(.*)\] ]]
              
              _pia_notify 'Disconnected from '"${BASH_REMATCH[1]:-vpn}"' ' 5000 "pia_off_48x48.png"
         fi

    else _logger "No current vpn connection"
  # NO
    fi

  # Can I reach the interwebs
    if ! ping -c 1  -W 1  -q 208.67.222.222 > /dev/null 2>&1
    then iptables-restore < "${MY_FIREWALL:=openrules.v4}"
  # No
         _logger "restored ${MY_FIREWALL} firewall"

    else _logger "pinged interwebs"
  # Yes
    fi

  # Check if we can dig it
    if ! dig +time=1 +tries=1 privateinternetaccess.com >/dev/null
    then _logger "restoring DNS nameservers"
  # No, restore known nameservers

         if [ -f /storage/.cache/starting_resolv.conf ]
         then cp -v /storage/.cache/starting_resolv.conf /run/connman/resolv.conf |
       # copy /etc/resolv.conf saved at system start by pre_up.sh
              tee >(_logger)

         else _logger "no preexisting resolv.conf winging it"
       # create a new resolv.conf from connman settings

            # already have array of services  
              while read -r line # 1000x 4.72s
              do [[ ! "${line}" =~ .*vpn_ ]] \
                   && non_vpn+=("$line")
              done < <( printf '%s\n' "${services[@]}")

            # get nameserver from first active non vpn_ interface settings

              nl=$'\n'
              mapfile -t settings < /storage/.cache/connman/"${non_vpn[0]##* }"/settings
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
    fi

  # timeout for systemd's sake
    max_count=15

    until ping -c 1 -W 1 -q privateinternetaccess.com > /dev/null
    do  ((count++))
  # wait for full connection
      # end at some point
        sleep 2

        if [[ "${count}" -gt "${max_count}" ]]
        then _logger "Interwebs failed after half a minute"
       # wait 30 seconds and exit, using $count as exit status
       # this stops systemd
             exit "${count}"
        fi
        _logger "Still waiting for full network access"
    done

    _logger "Have full network access"

  # port forwarding cleanup
    pf_pids=($(pidof port_forwarding.sh))

    if [ "${#pf_pids[@]}" -ne 0 ]
    then :> /tmp/port_forward.log
  # stop port forwarding 
         echo "${pf_pids[@]}" |
         xargs -d $'\n' sh -c 'for pid do kill -9 -$pid 2>/dev/null; wait $pid 2>/dev/null; done' _
         _logger "Stopped port forwarding"
         
    fi

################ Add other applications to stop below #################
#
exit 0
