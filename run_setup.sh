#!/opt/bin/bash
# Copyright (C) 2020 Private Internet Access, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
##
# modified for coreELEC/connman plgroves gmail 2022 #
# grep -n '\#$' *.sh to view changes #
# FORCED VPN_PROTOCOL TO Wireguard #
# changed path from /opt to /opt/etc #
# added kodi onscreen notifications #
# added variable check when run as a service #
# save token file and latency list for later use #
# forced DISABLE_IPV6 #
# ignored resolvconf dependency #
#
####
# to run without interaction
# PIA_USER=pXXXXXXX  PIA_PASS=P455w0rd AUTOCONNECT=true PIA_DNS=true|false PIA_PF=true|false ./run_setup.sh 
# the more variables you set the less interactive

  # PIA's scripts are set to a relative path #
    cd "${0%/*}" || exit 1 #

    export PATH=/opt/bin:/opt/sbin:"${PATH}" #

  # add kodi GUI.Notifications #
  #     _pia_notify 'message' 'display time' 'image file' #
  # and logging #
  #     _logger 'message' [ logfile ] #
  # get file creation time 
  # check interval now - then
  # convert seconds to 'X hrs Y mins Z secs'
  # check for empty/unset variables n.b. test unset passes VARIABLE NAME ONLY
  # check is interactive or not
  #
    [ -z "${kodi_user}" ] \
    && source ./kodi_assets/functions #

# DEBUGGING # systemd logs to journal env LOG=/dev/null #
#LOG="${LOG:-/tmp/pia-wireguard.log}" #
#:> "${LOG}" #
#exec > >(tee -a $LOG) #2>&1 #
#echo "Starting $(pwd)/${BASH_SOURCE##*/}" | tee >(_logger) #

  # How was this script called [systemd|favourites|interactively] #
  # systemd: continue #
  # favourites: pia-wireguard.service exist? #
  #             YES: (re)start service #
  #             NO: set logfile and continue #
  # interactively: set PRE_UP_RUN to cli #
  # 
    if #
    _is_unset PRE_UP_RUN \
      && \
    _is_not_tty \
      && \
    [[ "$( wc -l < <(systemctl list-unit-files pia-wireguard.service))" -gt 3 ]] #
  # not called by systemd or interactively, and systemd service exists #
    then systemd-cat -t pia-wireguard.favourites -p warning \
                     <<< "(Re)starting pia-wireguard.service from outside of systemd" #
       # log this to systemd journal and pia-wireguard log #
         LOG=/tmp/pia-wireguard.log _logger 'Called outside of systemd. Service is '" $(systemctl is-active  pia-wireguard.service)"'' #
       # optional Gui notificaton #
         #_pia_notify 'Called outside of systemd service is '" $(systemctl is-active  pia-wireguard.service)"'' ; sleep 5 #

         case "$(systemctl --quiet is-active  pia-wireguard.service; echo $?)" #
       # is service active #
         in #
              0|true)  SRe='Res' #
                       systemctl restart pia-wireguard.service & #
                     ;; #
              *|false) SRe='S' #
                       systemctl start pia-wireguard.service & #
             ;; #
         esac #

         systemd-cat -t pia-wireguard.favourites -p info <<< "${SRe}tarted pia-wireguard.service" #
       # log this to systemd journal and pia-wireguard log #
         LOG=/tmp/pia-wireguard.log _logger "${SRe}tarted pia-wireguard.service" #

         exit 0 #

    elif #
    _is_unset PRE_UP_RUN \
       && \
    _is_not_tty #
  # NO systemd, set LOG #
    then export LOG="${LOG:-/tmp/pia-wireguard.log}" #
         _logger "found no systemd service logging to ${LOG}" #
         _pia_notify "logging to ${LOG}" #
       # force displaytime #
         sleep 5 #

    elif _is_unset PRE_UP_RUN #
  # run is interactive: set PRE_UP_RUN #
    then export PRE_UP_RUN='cli' #
    fi #

  # possible variables for .env #
    # REQUIRED: when not running from a shell #
      #   PIA_USER='pXXXXXXX' #
      #   PIA_PASS='p45sw0rdxx' #
      #
    # one of #
      #   PREFERRED_REGION= [ run PIA_PF=(true|false) ./get_region ] #
      #         OR #
      #   AUTOCONNECT='false|true' n.b. AUTOCONNECT='true' overrides PREFERRED_REGION #
      #                                 AUTOCONNECT='false' sets MAX_LATENCY=0.05 #
      #                                 and it will run through all available servers #
      #                                 which takes a long time om a post-modem world #
      #         OR #
      #   export CONNMAN_CONNECT='true|false' n.b. this is set in the service file #
      #
    # optional #
      #   PIA_PF='true|false' (default false) #
      #   PIA_DNS='true|false' (default true) #
      #   MAX_LATENCY=99-0.001 (default is 0.05 if that doesn't work raise it) #
      #
      # these variable are not included in the pia scripts #
      #               THEY MUST BE EXPORTED #
      # if you want to use a custom set of iptables rules then define them here #
      #   export MY_FIREWALL=/path/to/my/iptables/openrules.v4 #
      #   export WG_FIREWALL=/path/to/my/iptables/openrules.v4 #

  # systemd checks for non empty .env file, so should we #
  #     ConditionFileNotEmpty=/storage/sources/pia-wireguard/.env & $PRE_UP_RUN #
    if [[ -s .env ]] #
  # read variables from .env file #
    then _logger "Load .env file"
         source .env  #

    elif _is_tty #
  # run is interactive w/o a .env file #
    then echo "Get ready to rumble" #

    else _pia_notify "No valid PIA config -> $(pwd)/.env" 10000 #
  # fail without minimal .env file #
         sleep 10
         _pia_notify "CONNECTION FAILED" 100000 #
         exit 1 #
    fi #

  # changes in .env file? # NOTE to self when disconnecting touch pia.config to reset creation time
  # If NO and pia.config is < 24hrs old, skip to ./post_up.sh #
    if #
    _is_not_tty \
      && \
    [[ -s /opt/etc/piavpn-manual/sha1sum.env ]] #
  # not running interactively, have checksum for previous .env #
    then _logger "    Checking current .env file with previous" #

         if [[ $(</opt/etc/piavpn-manual/sha1sum.env) = $(sha1sum .env) ]] #
       # .env is unchanged #
         then _logger "    .env is unchanged" #

              age_pia_config="$(_interval "$(_created ~/.config/wireguard/pia.config)")" #
              if [[ "${age_pia_config}" -lt $((24*60*60)) ]] #
            # wireguard/pia.config is less that 24 hours old   #
              then _logger "    pia.config is $(_hmmss "${age_pia_config}") old" #

                 # exit for systemd ExecStartPost, or call ./post_up.sh & exit for favourites #
                   case "${PRE_UP_RUN}" in #
                        t*) exit 0 ;; #
                      # systemd calls ./post_up.sh  
                        *)  ./post_up.sh & exit 0 ;; #
                   esac
              fi #

         else  _logger "      .env file has changed, running thru setup" #
       # Save checksum for new file #
               sha1sum .env > /opt/etc/piavpn-manual/sha1sum.env #
         fi #

    elif ! [[ -s /opt/etc/piavpn-manual/sha1sum.env ]] #
  # create /opt/etc/piavpn-manual/sha1sum.env #
    then sha1sum .env > /opt/etc/piavpn-manual/sha1sum.env #
         echo "saving sha1sum .env > /opt/etc/piavpn-manual/sha1sum.env" #

    else echo "Running interactively skipped checksum and .env check" #
  # running interactively #
    fi #

  # NON-INTERACTIVE VARIABLE CHECK #
    if _is_not_tty #
  # running non-interactive kit check" #
    then #

       # display time in ms for IMPORTANT NOTIFICATIONS _pia_notify '${BOTHER}' #
       # kodi won't wait so you will have to sleep $((BOTHER/1000)). Hence it's a bother.
         export BOTHER=14000 #

       # Check credentials #
         if #
         _is_empty "${PIA_USER}" \
          || 
         _is_empty "${PIA_PASS}" #
       # NO CREDENTIALS, we can forgetabout it #
         then _pia_notify "Missing PIA Credentials" "${BOTHER}" #
              sleep "$((BOTHER/1000+1))" #
              _pia_notify "CONNECTION FAILED" "$((BOTHER-5000))"#
              exit 1 #
         fi #

       # PREFERRED_REGION|AUTOCONNECT will create a connman config  with no interaction #
       # AUTOCONNECT|CONNMAN_CONNECT = false|null requires using Settings > CoreELEC > Connections #
       #   and sets NO FIREWALL or port forwarding #
         if #
         _is_empty "${PREFERRED_REGION}" \
          || 
         _is_empty "${AUTOCONNECT}" \
          || 
         _is_empty "${MAX_LATENCY}" #
       # Set them #
         then 
                function _AUTOCONNECT_or_PREFERRED_REGION() { #
              # AUTOCONNECT=true negates PREFERRED_REGION
                    if [[ "${AUTOCONNECT}" =~ ^t ]] #
                    then echo "the fastest server" #
                         _pia_notify 'AUTOCONNECT=true OVERRIDES PREFERRED_REGION='"${PREFERRED_REGION}"'' "$((BOTHER/2))" #
                         sleep "$((BOTHER/2000))" #
                    else echo "${PREFERRED_REGION}" #
                    fi #
               }

              # Set AUTOCONNECT="${AUTOCONNECT:-false}" and go from there #
                AUTOCONNECT="${AUTOCONNECT:-false}" # Keep AUTOCONNECT if set #
                if ! _is_empty "${PREFERRED_REGION}" #
              # RESOLVE AUTOCONNECT:PREFERRED_REGION CONFLICT #
                then via="$(_AUTOCONNECT_or_PREFERRED_REGION)" #
                else 
              # PREFERRED_REGION not set #
                     [[ "${AUTOCONNECT}" =~ ^f ]] \
                     && MAX_LATENCY="${MAX_LATENCY:=0.05}" #
                     via="the fastest server" #
                fi #
         elif _is_empty "${MAX_LATENCY}"
       # RESOLVE AUTOCONNECT:PREFERRED_REGION CONFLICT #
         then via="$(_AUTOCONNECT_or_PREFERRED_REGION)" #
         fi #

       # BOTHER ABOUT PREFERRED_REGION='' BECAUSE IT MAKES THE SCRIPT TAKE A LONG TIME?! #
         _is_empty "${PREFERRED_REGION}" \
                   && { _pia_notify "PREFERRED_REGION is unset this will take a while" "${BOTHER}";
                        sleep "$((BOTHER/1000))"; } #

       # Set PIA_PF and PIA_DNS. Notify if forcing PIA_DNS #
         PIA_PF="${PIA_PF:-false}" #

         if _is_empty "${PIA_DNS}" #
         then export PIA_DNS='true' #
              _pia_notify "FORCED PIA DNS" #
              sleep 2
         fi #

         _pia_notify 'getting details for '"${via}"'' #
    fi #

  # PRE_UP_RUN is set true by systemd, and 'cli' if _is_tty #
  # if not set then call ./pre_up.sh
    if _is_unset PRE_UP_RUN #
  # No systemd service or not running interactively #
    then #:> "${LOG}" #
         _logger "Setting up sane environment" #
         ./pre_up.sh #
    fi #

# end of major changes

# Check if terminal allows output, if yes, define colors for output
if [[ -t 1 ]]; then
  ncolors=$(tput colors 2>/dev/null)
  if [[ -n $ncolors && $ncolors -ge 8 ]]; then
    red=$(tput setaf 1) # ANSI red
    green=$(tput setaf 2) # ANSI green
    nc=$(tput sgr0) # No Color
  else
    red=''
    green=''
    nc='' # No Color
  fi
fi

# Variables to use for validating input
intCheck='^[0-9]+$'
floatCheck='^[0-9]+([.][0-9]+)?$'

# Only allow script to run as root
if (( EUID != 0 )); then
  echo -e "${red}This script needs to be run as root. Try again with 'sudo $0'${nc}"
  exit 1
fi

    # Erase previous authentication token if present
    # changed paths from /opt/ #
    # and commented rm token as it can be used for 24 hrs #
    #rm -f /opt/etc/piavpn-manual/token /opt/etc/piavpn-manual/latencyList #
    #rm -f /opt/etc/piavpn-manual/latencyList #

# Retry login if no token is generated
while :; do
    while :; do
      # Check for in-line definition of $PIA_USER
      if [[ -z $PIA_USER ]]; then
        echo
        read -r -p "PIA username (p#######): " PIA_USER
      fi

      # Confirm format of PIA_USER input
      unPrefix=${PIA_USER:0:1}
      unSuffix=${PIA_USER:1}
      if [[ -z $PIA_USER ]]; then
        echo -e "\n${red}You must provide input.${nc}"
      elif [[ ${#PIA_USER} != 8 ]]; then
        echo -e "\n${red}A PIA username is always 8 characters long.${nc}"
      elif [[ $unPrefix != "P" ]] && [[ $unPrefix != "p" ]]; then
        echo -e "\n${red}A PIA username must start with \"p\".${nc}"
      elif ! [[ $unSuffix =~ $intCheck ]]; then
        echo -e "\n${red}Username formatting is always p#######!${nc}"
      else
        echo -e "\n${green}PIA_USER=$PIA_USER${nc}"
        break
      fi
      PIA_USER=""
    done
  export PIA_USER

  while :; do
    # Check for in-line definition of $PIA_PASS
    if [[ -z $PIA_PASS ]]; then
      echo
      echo -n "PIA password: "
      read -r -s PIA_PASS
      echo
    fi

    # Confirm format of PIA_PASS input
    if [[ -z $PIA_PASS ]]; then
      echo -e "\n${red}You must provide input.${nc}"
    elif [[ ${#PIA_PASS} -lt 8 ]]; then
      echo -e "\n${red}A PIA password is always a minimum of 8 characters long.${nc}"
    else
      echo -e "\n${green}PIA_PASS input received.${nc}"
      echo
      break
    fi
    PIA_PASS=""
  done
  export PIA_PASS

  # Confirm credentials and generate token
  ./get_token.sh
# DEBUGGING
echo REGION CHECKED BEFORE THIS
          # changed tokenLocation #
            tokenLocation="/opt/etc/piavpn-manual/token" #
  # If the script failed to generate an authentication token, the script will exit early.
  if [[ ! -f $tokenLocation ]]; then
    read -r -p "Do you want to try again ([N]o/[y]es): " tryAgain
    if ! echo "${tryAgain:0:1}" | grep -iq y; then
      exit 1
    fi
    PIA_USER=""
    PIA_PASS=""
  else
          # read from saved token file
            PIA_TOKEN=$( awk 'NR == 1' /opt/etc/piavpn-manual/token ) #
    export PIA_TOKEN
# token is good for 24 hours according to PIA #
    #rm -f /opt/etc/piavpn-manual/token #
    break
  fi
done

# Check for in-line definition of PIA_PF and prompt for input
if [[ -z $PIA_PF ]]; then
  echo -n "Do you want a forwarding port assigned ([N]o/[y]es): "
  read -r portForwarding
  echo
  if echo "${portForwarding:0:1}" | grep -iq y; then
    PIA_PF="true"
  fi
fi
if [[ $PIA_PF != "true" ]]; then
 PIA_PF="false"
fi
export PIA_PF
echo -e "${green}PIA_PF=$PIA_PF${nc}"
echo

    # Wireguard and ipv6 are not supported by Private Internet Access #
      export DISABLE_IPV6=yes #

# Check for in-line definition of DISABLE_IPV6 and prompt for input
if [[ -z $DISABLE_IPV6 ]]; then
  echo "Having active IPv6 connections might compromise security by allowing"
  echo "split tunnel connections that run outside the VPN tunnel."
  echo -n "Do you want to disable IPv6? (Y/n): "
  read -r DISABLE_IPV6
  echo
fi

if echo "${DISABLE_IPV6:0:1}" | grep -iq n; then
  echo -e "${red}IPv6 settings have not been altered.
  ${nc}"
else
     if _is_tty #
   # Running interactively #
     then #
  echo -e "The variable ${green}DISABLE_IPV6=$DISABLE_IPV6${nc}, does not start with 'n' for 'no'.
${green}Defaulting to yes.${nc}
"
  echo
  echo -e "${red}IPv6 has been disabled${nc}, you can ${green}enable it again with: "
  echo "sysctl -w net.ipv6.conf.all.disable_ipv6=0"
  echo "sysctl -w net.ipv6.conf.default.disable_ipv6=0"
  echo -e "${nc}"
     else _pia_notify "IPv6 has been disabled" #
     fi #
  sysctl -w net.ipv6.conf.all.disable_ipv6=1
  sysctl -w net.ipv6.conf.default.disable_ipv6=1
  echo
fi

# Input validation and check for conflicting declarations of AUTOCONNECT and PREFERRED_REGION
# If both variables are set, AUTOCONNECT has superiority and PREFERRED_REGION is ignored
if [[ -z $AUTOCONNECT ]]; then
  echo "AUTOCONNECT was not declared."
  echo
  selectServer="ask"
elif echo "${AUTOCONNECT:0:1}" | grep -iq f; then
  if [[ $AUTOCONNECT != "false" ]]; then
    echo -e "The variable ${green}AUTOCONNECT=$AUTOCONNECT${nc}, starts with 'f' for 'false'."
    AUTOCONNECT="false"
    echo -e "Updated ${green}AUTOCONNECT=$AUTOCONNECT${nc}"
    echo
  fi
  selectServer="yes"
else
  if [[ $AUTOCONNECT != "true" ]]; then
    echo -e "The variable ${green}AUTOCONNECT=$AUTOCONNECT${nc}, does not start with 'f' for 'false'."
    AUTOCONNECT="true"
    echo -e "Updated ${green}AUTOCONNECT=$AUTOCONNECT${nc}"
    echo
  fi
  if [[ -z $PREFERRED_REGION ]]; then
    echo -e "${green}AUTOCONNECT=true${nc}"
    echo
  else
    echo
    echo "AUTOCONNECT supersedes in-line definitions of PREFERRED_REGION."
    echo -e "${red}PREFERRED_REGION=$PREFERRED_REGION will be ignored.${nc}
    "
    PREFERRED_REGION=""
  fi
  selectServer="no"
fi
  # pia-foss manual connections does not export AUTOCONNECT #
  # needed at connection step in post_up.sh  #
    export AUTOCONNECT #
# Prompt the user to specify a server or auto-connect to the lowest latency
while :; do
  if [[ -z $PREFERRED_REGION ]]; then
    # If autoconnect is not set, prompt the user to specify a server or auto-connect to the lowest latency
    if [[ $selectServer == "ask" ]]; then
      echo -n "Do you want to manually select a server, instead of auto-connecting to the
server with the lowest latency ([N]o/[y]es): "
      read -r selectServer
      echo
    fi

    # Call the region script with input to create an ordered list based upon latency
    # When $PREFERRED_REGION is set to none, get_region.sh will generate a list of servers
    # that meet the latency requirements specified by $MAX_LATENCY.
    # When $VPN_PROTOCOL is set to no, get_region.sh will sort that list of servers
    # to allow for numeric selection, or an easy manual review of options.
    if echo "${selectServer:0:1}" | grep -iq y; then
      # This sets the maximum allowed latency in seconds.
      # All servers that respond slower than this will be ignored.
      if [[ -z $MAX_LATENCY ]]; then
        echo -n "With no input, the maximum allowed latency will be set to 0.05s (50ms).
If your connection has high latency, you may need to increase this value.
For example, you can try 0.2 for 200ms allowed latency.
"
      else
        latencyInput=$MAX_LATENCY
      fi

      # Assure that input is numeric and properly formatted.
# Check this  latencyInput=$MAX_LATENCY then MAX_LATENCY=$latencyInput #
      MAX_LATENCY=0.05
      while :; do
        if [[ -z $latencyInput ]]; then
          read -r -p "Custom latency (no input required for 50ms): " latencyInput
          echo
        fi
        customLatency=0
        customLatency+=$latencyInput

        if [[ -z $latencyInput ]]; then
          break
        elif [[ $latencyInput == 0 ]]; then
          echo -e "${red}Latency input must not be zero.${nc}\n"
        elif ! [[ $customLatency =~ $floatCheck ]]; then
          echo -e "${red}Latency input must be numeric.${nc}\n"
        elif [[ $latencyInput =~ $intCheck ]]; then
          MAX_LATENCY=$latencyInput
          break
        else
# CHECK THIS it removes the leading zero #
          MAX_LATENCY="${customLatency:1}" #
          break
        fi
        latencyInput=""
      done
# CHECK THIS
      echo -e "${green}MAX_LATENCY=${MAX_LATENCY:=0.05}${nc}"
      export MAX_LATENCY

      PREFERRED_REGION="none"
      export PREFERRED_REGION
# we don't need to mess with VPN_PROTOCOL #
#      VPN_PROTOCOL="no" #
#      export VPN_PROTOCOL #
                          # to limit kodi onscreen notification #
            VPN_PROTOCOL=no IVE_RUN=0 ./get_region.sh 2>/dev/null #

      if [[ -s /opt/etc/piavpn-manual/latencyList ]]; then #
        # Output the ordered list of servers that meet the latency specification $MAX_LATENCY
                if _is_tty #
              # RUNNING INTERACTIVELY #
                then #
        echo -e "Ordered list of servers with latency less than ${green}${MAX_LATENCY}${nc} seconds:" #
        i=0
        while read -r line; do
          i=$((i+1))
            # modified path #
            time=$( awk 'NR == '$i' {print $1}' /opt/etc/piavpn-manual/latencyList ) #
            id=$( awk 'NR == '$i' {print $2}' /opt/etc/piavpn-manual/latencyList ) #
            ip=$( awk 'NR == '$i' {print $3}' /opt/etc/piavpn-manual/latencyList ) #
            location1=$( awk 'NR == '$i' {print $4}' /opt/etc/piavpn-manual/latencyList ) #
            location2=$( awk 'NR == '$i' {print $5}' /opt/etc/piavpn-manual/latencyList ) #
            location3=$( awk 'NR == '$i' {print $6}' /opt/etc/piavpn-manual/latencyList ) #
            location4=$( awk 'NR == '$i' {print $7}' /opt/etc/piavpn-manual/latencyList ) #
          location="$location1 $location2 $location3 $location4"
          printf "%3s : %-8s %-15s %17s" $i "$time" "$ip" "$id"
          echo " - $location"
        done <      /opt/etc/piavpn-manual/latencyList #
        echo

        # Receive input to specify the server to connect to manually
        while :; do
          read -r -p "Input the number of the server you want to connect to ([1]-[$i]) : " serverSelection
            if [[ -z $serverSelection ]]; then
              echo -e "\n${red}You must provide input.${nc}\n"
            elif ! [[ $serverSelection =~ $intCheck ]]; then
              echo -e "\n${red}You must enter a number.${nc}\n"
            elif [[ $serverSelection -lt 1 ]]; then
              echo -e "\n${red}You must enter a number greater than 1.${nc}\n"
            elif [[ $serverSelection -gt $i ]]; then
              echo -e "\n${red}You must enter a number between 1 and $i.${nc}\n"
            else
                    PREFERRED_REGION=$( awk 'NR == '"$serverSelection"' {print $2}' /opt/etc/piavpn-manual/latencyList ) #
              echo
              echo -e "${green}PREFERRED_REGION=$PREFERRED_REGION${nc}"
              break
            fi
        done

        # Write the serverID for use when connecting, and display the serverName for user confirmation
        export PREFERRED_REGION
        echo
        break
              # running non-interactively got ordered list choosing fastest #
                else # choose best region and proceed #
                     PREFERRED_REGION=$( awk 'NR == '1' {print $2}' /opt/etc/piavpn-manual/latencyList ) # 
                     REGION="$(/opt/bin/jq -r '.name' < /opt/etc/piavpn-manual/regionData )" #
                     export PREFERRED_REGION #
                     _pia_notify 'Selected for '"${REGION}"'' #
                fi #
      else # [[ ! -s /opt/etc/piavpn-manual/latencyList ]]
           if _is_not_tty #
         # RUNNING NON-INTERACTIVELY #
           then #
                _pia_notify "No Available Servers Found!" "${BOTHER}" #
                _logger "No Available Servers Found!" #
           fi #
        exit 1
      fi
    else
      echo -e "${green}You will auto-connect to the server with the lowest latency.${nc}"
      echo
      break
    fi
  else
    # Validate in-line declaration of PREFERRED_REGION; if invalid remove input to initiate prompts
    echo "Region input is : $PREFERRED_REGION"
    export PREFERRED_REGION   # added to supress kodi notifications #
                VPN_PROTOCOL=no IVE_RUN='1' ./get_region.sh 2>/dev/null # 
    if [[ $? != 1 ]]; then
      break
    fi
    PREFERRED_REGION=""
  fi
done

if [[ -z $VPN_PROTOCOL ]]; then
              # these scipts are for wireguard only! #
                export VPN_PROTOCOL="wireguard" #
fi
# This section asks for user connection preferences
case $VPN_PROTOCOL in
  openvpn)
    VPN_PROTOCOL="openvpn_udp_standard"
    ;;
  wireguard | openvpn_udp_standard | openvpn_udp_strong | openvpn_tcp_standard | openvpn_tcp_strong)
    ;;
  none | *)
    echo -n "Connection method ([W]ireguard/[o]penvpn): "
    read -r connection_method
    echo

    VPN_PROTOCOL="wireguard"
    if echo "${connection_method:0:1}" | grep -iq o; then
      echo -n "Connection method ([U]dp/[t]cp): "
      read -r protocolInput
      echo

      protocol="udp"
      if echo "${protocolInput:0:1}" | grep -iq t; then
        protocol="tcp"
      fi

      echo "Higher levels of encryption trade performance for security. "
      echo -n "Do you want to use strong encryption ([N]o/[y]es): "
      read -r strongEncryption
      echo

      encryption="standard"
      if echo "${strongEncryption:0:1}" | grep -iq y; then
        encryption="strong"
      fi

      VPN_PROTOCOL="openvpn_${protocol}_${encryption}"
    fi
    ;;
esac
export VPN_PROTOCOL
echo -e "${green}VPN_PROTOCOL=$VPN_PROTOCOL
${nc}"

# Check for the required presence of resolvconf for setting DNS on wireguard connections
setDNS="yes"
if ! command -v resolvconf &>/dev/null && [[ $VPN_PROTOCOL == "wireguard" ]]; then
     if _is_tty #
   # Running interactively #
     then #
          echo -e "${red}The resolvconf package could not be found." #
          echo "This script can not set DNS for you" #
          echo -e "but connmanctl can.${nc}" #
          echo #
     fi #
  setDNS="no"
  # coreelec does not have resolvconf; we can modify the /run/connman/resolv.conf modified by connman #
     setDNS="yes" #
fi

# Check for in-line definition of PIA_DNS and prompt for input
if [[ $setDNS == "yes" ]]; then
  if [[ -z $PIA_DNS ]]; then
    echo "Using third party DNS could allow DNS monitoring."
    echo -n "Do you want to force PIA DNS ([Y]es/[n]o): "
    read -r setDNS
    echo
    PIA_DNS="true"
    if echo "${setDNS:0:1}" | grep -iq n; then
      PIA_DNS="false"
    fi
  fi
elif [[ $PIA_DNS != "true" || $setDNS == "no" ]]; then
  PIA_DNS="false"
fi
export PIA_DNS
  # WHY?
    export MAX_LATENCY #
echo -e "${green}PIA_DNS=$PIA_DNS${nc}"

CONNECTION_READY="true"
export CONNECTION_READY

  # added IVE_RUN to supress notify_kodi #
    IVE_RUN=2 ./get_region.sh 2>/dev/null #
