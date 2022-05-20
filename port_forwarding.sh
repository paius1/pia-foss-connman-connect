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
####
# modified for coreELEC/connman plgroves gmail 2022 #
# started with https://github.com/thrnz/docker-wireguard-pia/blob/master/extra/pf.sh #
#   trap exit and fatal error #
# MODIFIED from https://github.com/triffid/pia-wg/blob/master/pia-portforward.sh #
#   bind_port_response payload_and_signature #
# added logging, saving port to file and adding to firewall #
# 

  # PIA's scripts are set to a relative path #
    cd "${0%/*}" || exit 1 #

    export PATH=/opt/bin:/opt/sbin:"${PATH}" #

  # where to store the port number for later usage #
    portfile='/tmp/port.dat' #

    [[ -z "${kodi_user}" ]] \
      && source ./kodi_assets/functions #

# DEBUGGING
#LOG="${LOG:-/tmp/pia-wireguard.log}"
#_logger "Starting $(pwd)/${BASH_SOURCE##*/}"
#exec > >(tee -a $LOG) #2>&1

  # this can be run separately
    _is_tty \
       && export PRE_UP_RUN='cli' #
    export LOG="${LOG:=/tmp/pia-wireguard.log}" #

# This function allows you to check if the required tools have been installed.
check_tool() {
  cmd=$1
  if ! command -v "$cmd" >/dev/null; then
    echo "$cmd could not be found"
    echo "Please install $cmd"
    echo "Try running $(pwd)/entware-installer.sh " #
    echo "to install all dependencies " #
    exit 1
  fi
}
# Now we call the function to make sure we can use curl and jq.
# hard coded paths #
    check_tool /opt/bin/curl #
    check_tool /opt/bin/jq #

# Check if the mandatory environment variables are set.
if [[ -z $PF_GATEWAY || -z $PIA_TOKEN || -z $PF_HOSTNAME ]]; then
  echo "This script requires 3 env vars:"
  echo "PF_GATEWAY  - the IP of your gateway"
  echo "PF_HOSTNAME - name of the host used for SSL/TLS certificate verification"
  echo "PIA_TOKEN   - the token you use to connect to the vpn services"
  echo
  echo "An easy solution is to just run get_region_and_token.sh"
  echo "as it will guide you through getting the best server and"
  echo "also a token. Detailed information can be found here:"
  echo "https://github.com/pia-foss/manual-connections"
exit 1
fi

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

  # An error with no recovery logic occured #
    fatal_error () { #
        local port="${1}" #

        echo "Fatal error::port_forwarding.sh" |& #
        tee >(_logger) >(_pia_notify 6000 'pia_off_48x48.png') >/dev/null #
         sleep 6 #

      # remove port from iptables #
        iptables -D INPUT -p tcp --dport "${port}" -j ACCEPT #

        echo "Attempting restart of port forwarding" |& #
        tee >(_logger) >(_pia_notify 5000 'pia_off_48x48.png') >/dev/null  #

         function _get_token() { #
             if PIA_USER="${PIA_USER}" PIA_PASS="${PIA_PASS}" "$(pwd)"/get_token.sh #
             then return 0 #
             else return 1 #
             fi #
         } #

         if [[ -s "${tokenLocation:=/opt/etc/piavpn-manual/token}" ]] #
         then #
       # have tokenFile #
            # check expiry
            # https://stackoverflow.com/users/2318662/tharrrk
              m2n() { printf '%02d' $((-10+$(sed 's/./\U&/g;y/ABCEGLNOPRTUVY/60AC765A77ABB9/;s/./+0x&/g'<<<${1#?}) ));} #

              mapfile -t tokenFile < "${tokenLocation}" #
              month="${tokenFile[1]#* }" #
               month="${month%% *}" #
                month="$(m2n "${month}")" #
              expiry_iso="$(awk '{printf "%d-%02d-%02dT%s", $NF,$2,$3,$4}' < <( awk -v month="${month}" '$2=month' <<< "${tokenFile[1]}"))" #

            # compare iso dates #
              if (( $(date -d "+30 min" +%s) < $(date -d "${expiry_iso}" +%s) )) #
              then echo "Previous token OK!" #
            # less than 24hrs old #

              else echo "token expired saving a new one to ${tokenLocation}" #
            # day old, refresh  #
                   unset tokenFile #
                   _get_token \
                     && mapfile -t tokenFile < "${tokenLocation}" #
              fi #

         else #
       # get token #
              _get_token \
                && mapfile -t tokenFile < "${tokenLocation}" #
         fi

         if _is_set "${tokenFile[0]}" #
         then echo "    logging port_forwarding to /tmp/port_forward.log" |&
       # have token, proceed with ./port_forwarding.sh #
              tee >(_logger) >/dev/null #
    
        PIA_TOKEN="${tokenFile[0]}" PF_GATEWAY="${PF_GATEWAY}" PF_HOSTNAME="${PF_HOSTNAME}" \
        "$(pwd)"/port_forwarding.sh > /tmp/port_forward.log & #
         disown #
         else echo "Port Forwarding failed" |& #
              tee >(_logger) >(_pia_notify) >/dev/null #
              exit 1 #
         fi #

        exit 0 #
 } #

  # Handle shutdown #
    finish () { #
        echo "Port forward stopped, port will close soon." |
        tee >(_logger) >(_service_is_active pia-wireguard >/dev/null && _pia_notify 5000 'pia_off_48x48.png') >/dev/null #

        #_logger "Port forward rebinding stopped. The port will likely close soon." #

      # remove port from iptables #
        iptables -C INPUT -p tcp --dport "${port}" -j ACCEPT 2>/dev/null \
           && iptables -D INPUT -p tcp --dport "${port}" -j ACCEPT #

        exit 0 #
 }
    trap finish SIGTERM SIGINT SIGQUIT #

  # replace any currently running port_forwarding.sh's #
    pids=($(pidof port_forwarding.sh)) #
    mypid=$$ #

    if [ "${#pids[@]}" -gt 1 ] #
    then _logger "port_forwarding.sh is already running, will stop others" #
  # remove this instance from pids[@] #
         
         for i in "${!pids[@]}" #
         do if [ "${pids[$i]}" == "$mypid" ] #
            then unset pids["${i}"] #
            fi #
         done #

       # kill the remainders
         echo "${pids[@]}" |
         xargs -d $'\n' sh -c 'for pid do kill -9 $pid 2>/dev/null; wait $pid 2>/dev/null; done' _ #
    fi #

  # wait for privateinternetaccess this could be an infinite loop #
    until ping -c 1 -W 1  privateinternetaccess.com > /dev/null 2>&1 #
    do _logger "wait for privateinternetaccess" #
       sleep 5 #
       #connmanctl connect "${SERVICE}" || exit 0 #
       # maybe create a time out #
       # or just exit #
    done #

    >&2 echo -ne "\nStarting port forwarding in " #
    for i in {5..1} #
    do #
       >&2          echo -n "$i..." #
       sleep 1 #
    done #
    >&2        echo #

# The port forwarding system has required two variables:
# PAYLOAD: contains the token, the port and the expiration date
# SIGNATURE: certifies the payload originates from the PIA network.

# Basically PAYLOAD+SIGNATURE=PORT. You can use the same PORT on all servers.
# The system has been designed to be completely decentralized, so that your
# privacy is protected even if you want to host services on your systems.

# You can get your PAYLOAD+SIGNATURE with a simple curl request to any VPN
# gateway, no matter what protocol you are using. Considering WireGuard has
# already been automated in this repo, here is a command to help you get
# your gateway if you have an active OpenVPN connection:
# $ ip route | head -1 | grep tun | awk '{ print $3 }'
# This section will get updated as soon as we created the OpenVPN script.

# Get the payload and the signature from the PF API. This will grant you
# access to a random port, which you can activate on any server you connect to.
# If you already have a signature, and you would like to re-use that port,
# save the payload_and_signature received from your previous request
# in the env var PAYLOAD_AND_SIGNATURE, and that will be used instead.
if [[ -z $PAYLOAD_AND_SIGNATURE ]]; then
>&2  echo #
>&2  echo -n "Getting new signature... " #
  #payload_and_signature="$(curl -s -m 5 \
    #--connect-to "$PF_HOSTNAME::$PF_GATEWAY:" \
    #--cacert "ca.rsa.4096.crt" \
    #-G --data-urlencode "token=${PIA_TOKEN}" \
    #"https://${PF_HOSTNAME}:19999/getSignature")"

        # MODIFIED from https://github.com/triffid/pia-wg/blob/master/pia-portforward.sh #
            payload_and_signature="$( curl --interface wg0 --CAcert "ca.rsa.4096.crt" --get --silent --show-error --retry 5 --retry-delay 1 --max-time 2 --data-urlencode "token=${PIA_TOKEN}" --resolve "$PF_HOSTNAME:19999:$PF_GATEWAY" "https://$PF_HOSTNAME:19999/getSignature")" #
else
  payload_and_signature=$PAYLOAD_AND_SIGNATURE
  echo -n "Checking the payload_and_signature from the env var... "
fi
export payload_and_signature

# Check if the payload and the signature are OK.
# If they are not OK, just stop the script.
if [[ $(echo "$payload_and_signature" | jq -r '.status') != "OK" ]]; then
  echo -e "${red}The payload_and_signature variable does not contain an OK status.${nc}"
  exit 1
fi
>&2 echo -e "${green}OK!${nc}" #

# We need to get the signature out of the previous response.
# The signature will allow the us to bind the port on the server.
signature=$(echo "$payload_and_signature" | jq -r '.signature')

# The payload has a base64 format. We need to extract it from the
# previous response and also get the following information out:
# - port: This is the port you got access to
# - expires_at: this is the date+time when the port expires
payload=$(echo "$payload_and_signature" | jq -r '.payload')
port=$(echo "$payload" | base64 -d | jq -r '.port')

# The port normally expires after 2 months. If you consider
# 2 months is not enough for your setup, please open a ticket.
expires_at=$(echo "$payload" | base64 -d | jq -r '.expires_at')

    if [[ "${port}" =~ ^[0-9]+$ ]] #
    then #
  # Dump port to file if requested #
         [[ -n "$portfile" ]] \
           && { echo "${port}" > "$portfile" \
                && _logger "Port ${port} dumped to $portfile"; } #

       # add port to iptables #
         iptables -I INPUT -p tcp --dport "${port}" -j ACCEPT #
         _logger "added port ${port} to firewall" #

>&2 echo -ne "
--> The port is ${green}$port${nc} and it will expire on ${red}$expires_at${nc}. <--

Trying to bind the port... " #
    fi #
# Now we have all required data to create a request to bind the port.
# We will repeat this request every 15 minutes, in order to keep the port
# alive. The servers have no mechanism to track your activity, so they
# will just delete the port forwarding if you don't send keepalives.
while true; do
  #bind_port_response="$(curl -Gs -m 5 \
    #--connect-to "$PF_HOSTNAME::$PF_GATEWAY:" \
    #--cacert "ca.rsa.4096.crt" \
    #--data-urlencode "payload=${payload}" \
    #--data-urlencode "signature=${signature}" \
    #"https://${PF_HOSTNAME}:19999/bindPort")"

        # MODIFIED from https://github.com/triffid/pia-wg/blob/master/pia-portforward.sh #
                bind_port_response="$( curl --interface wg0 --CAcert "ca.rsa.4096.crt" --get --silent --show-error --retry 5 --retry-delay 1 --max-time 2 --data-urlencode "payload=${payload}" --data-urlencode "signature=${signature}"  --resolve "$PF_HOSTNAME:19999:$PF_GATEWAY" "https://$PF_HOSTNAME:19999/bindPort" )" #

    # If port did not bind, just exit the script.
    # This script will exit in 2 months, since the port will expire.
    if [[ $(echo "$bind_port_response" | jq -r '.status') != "OK" ]]; then
      echo -e "${red}The API did not return OK when trying to bind port... Exiting.${nc}"
            fatal_error "${port}" #
    fi
    export bind_port_response
>&2    echo -e "${green}OK!${nc}" #
>&2    echo #

        if [ -z "${pf_firstrun+y}" ] #
        then ((pf_firstrun++))
  ( echo -e Forwarded port'\t'"${green}$port${nc}" #
    echo -e Refreshed on'\t'"${green}$(date)${nc}"
    echo -e Expires on'\t'"${red}$(date --date="$expires_at")${nc}"
    echo -e "\n${green}This script will need to remain active to use port forwarding, and will refresh every 15 minutes.${nc}\n"
  ) |& #
  tee >(_logger) >/dev/null #
        else _logger "Rebinding to port ${port} @ $(date +'%I:%M:%S %D')" #
        fi #

    # sleep 15 minutes
    sleep 900
done
