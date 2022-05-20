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
# hard coded/changed paths #
# converts wg-quick conf to connman config #
# add post_up.sh #

  # PIA's scripts are set to a relative path #
    cd "${0%/*}" || exit 255 #

    export PATH=/opt/bin:/opt/sbin:"${PATH}" #

    [[ -z "${kodi_user}" ]] \
      && source ./kodi_assets/functions #

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

# PIA currently does not support IPv6. In order to be sure your VPN
# connection does not leak, it is best to disabled IPv6 altogether.
# IPv6 can also be disabled via kernel commandline param, so we must
# first check if this is the case.
if [[ -f /proc/net/if_inet6 ]] &&
  [[ $(sysctl -n net.ipv6.conf.all.disable_ipv6) -ne 1 ||
     $(sysctl -n net.ipv6.conf.default.disable_ipv6) -ne 1 ]]
then
  echo -e "${red}You should consider disabling IPv6 by running:"
  echo "sysctl -w net.ipv6.conf.all.disable_ipv6=1"
  echo -e "sysctl -w net.ipv6.conf.default.disable_ipv6=1${nc}"
fi

# Check if the mandatory environment variables are set.
if [[ -z $WG_SERVER_IP ||
      -z $WG_HOSTNAME ||
      -z $PIA_TOKEN ]]; then
  echo -e "${red}This script requires 3 env vars:"
  echo "WG_SERVER_IP - IP that you want to connect to"
  echo "WG_HOSTNAME  - name of the server, required for ssl"
  echo "PIA_TOKEN    - your authentication token"
  echo
  echo "You can also specify optional env vars:"
  echo "PIA_PF                - enable port forwarding"
  echo "PAYLOAD_AND_SIGNATURE - In case you already have a port."
  echo
  echo "An easy solution is to just run get_region_and_token.sh"
  echo "as it will guide you through getting the best server and"
  echo "also a token. Detailed information can be found here:"
  echo -e "https://github.com/pia-foss/manual-connections${nc}"
  exit 1
fi

# Create ephemeral wireguard keys, that we don't need to save to disk.
privKey=$(wg genkey)
export privKey
pubKey=$( echo "$privKey" | wg pubkey)
export pubKey

# Authenticate via the PIA WireGuard RESTful API.
# This will return a JSON with data required for authentication.
# The certificate is required to verify the identity of the VPN server.
# In case you didn't clone the entire repo, get the certificate from:
# https://github.com/pia-foss/manual-connections/blob/master/ca.rsa.4096.crt
# In case you want to troubleshoot the script, replace -s with -v.
echo "Trying to connect to the PIA WireGuard API on $WG_SERVER_IP..."

wireguard_json="$(curl -s -G \
  --connect-to "$WG_HOSTNAME::$WG_SERVER_IP:" \
  --cacert "ca.rsa.4096.crt" \
  --data-urlencode "pt=${PIA_TOKEN}" \
  --data-urlencode "pubkey=$pubKey" \
  "https://${WG_HOSTNAME}:1337/addKey" | tee /opt/etc/piavpn-manual/wireguard_json )" #
  # added tee to save wireguard_json output
export wireguard_json

# Check if the API returned OK and stop this script if it didn't.
if [[ $(echo "$wireguard_json" | /opt/bin/jq -r '.status') != "OK" ]]; then #
  >&2 echo -e "${red}Server did not return OK. Stopping now.${nc}"
            echo  "Server did not return OK. Stopping now." |& #
            tee >(_logger) >(_is_not_tty && _pia_notify  '10000' 'pia_off_48x48.png') >/dev/null #
          # added for non-interactive #
  exit 1
fi
          # backup wireguard_json
            echo "${wireguard_json}" > /opt/etc/piavpn-manual/wireguard_json-"${WG_HOSTMANE}" #

# Create the WireGuard config based on the JSON received from the API
# In case you want this section to also add the DNS setting, please
# start the script with PIA_DNS=true.
# This uses a PersistentKeepalive of 25 seconds to keep the NAT active
# on firewalls. You can remove that line if your network does not
# require it.
if [[ $PIA_DNS == "true" ]]; then
  dnsServer=$(echo "$wireguard_json" | /opt/bin/jq -r '.dns_servers[0]')
            if _is_tty #
            then #
          # running interactively #
  echo #
  echo "Set up DNS to $dnsServer. Since we do not have resolvconf," #
  echo "we will rely on connman to set nameservers" #
  echo "and ensure ${dnsServer} is the first one" #
  echo
            fi #
  dnsSettingForVPN="DNS = ${dnsServer}"
fi
echo -n "Trying to write /opt/etc/wireguard/pia.conf..."
          # changed path #
            mkdir -p /opt/etc/wireguard #

  # Verify overwriting system generated file from tty #
  # appended  '-cli'? #
    if _is_tty \
         &&
       [[ -s /opt/etc/wireguard/pia.conf ]] #
    then printf '%s\n' "exists, overwrite? ([N]o/[y]es): " #
  # overwrite existing pia.conf running interactively #
  # (default is Yes, No to add -cli to filename #
         shopt -s nocasematch
         read -r continue #
         if [[ "${continue}" != *"y"* ]] #
         then plus='-cli' #
       # NO, add '-cli' to file name #
              echo -n "writing to /opt/etc/wireguard/pia${plus}.conf..."
         fi #
         shopt -u nocasematch
    fi #

echo "
[Interface]
Address = $(echo "$wireguard_json" | /opt/bin/jq -r '.peer_ip')
PrivateKey = $privKey
ListenPort = $(echo "$wireguard_json" | /opt/bin/jq -r '.server_port')
$dnsSettingForVPN
[Peer]
PersistentKeepalive = 25
PublicKey = $(echo "$wireguard_json" | /opt/bin/jq -r '.server_key')
AllowedIPs = 0.0.0.0/0
Endpoint = ${WG_SERVER_IP}:$(echo "$wireguard_json" | /opt/bin/jq -r '.server_port')
" > /opt/etc/wireguard/pia"${plus}".conf || exit 1 # changed path and name #
echo -e "${green}OK!${nc}"
    echo #

  # backup wireguard pia${plus}.conf
    cp -v /opt/etc/wireguard/pia"${plus}".conf /opt/etc/wireguard/pia"${plus}-${WG_HOSTNAME}".conf~ #

  # LibreElec doesn't include the iptables_raw kernel module #
  # so it's not possible to set AllowedIps as 0.0.0.0/0 with wg-quick #
  # CONNMAN sets up the interface, ignore wg-quick #

    echo -n "Trying to write connman pia.config..." #

  # Verify overwriting system generated file from tty #
  # default append '-(user_added)'? #
    if _is_tty \
         &&
       [[ -s /storage/.config/wireguard/pia.config ]] #
    then printf '%s\n' "exists, overwrite? ([N]o/[y]es): " #
  # overwrite existing pia.config running interactively? #
         shopt -s nocasematch
         read -r continue #
         if [[ "${continue}" != *"y"* ]] #
         then cli='-(user_added)' #
       # NO, add '-(user added)' #

              echo -n "writing to /storage/.config/wireguard/pia${cli}.config..."
              export cli #
            # export for post_up.sh #
         fi #
         shopt -u nocasematch
    fi #

  # convert wireguard .conf to connman .config #

  # read pia${plus}.conf into variables #
    declare Address PrivateKey PersistentKeepalive PublicKey AllowedIPs Endpoint #
    eval "$(grep -e '^[[:alpha:]]' /opt/etc/wireguard/pia"${plus}".conf | sed 's| = |=|')" #
    REGION_NAME="$(_parse_JSON 'name' < /opt/etc/piavpn-manual/regionData)" #

  # write wireguard config #
    cat <<-EOF > /storage/.config/wireguard/pia"${cli}".config
    [provider_wireguard]
    Type = WireGuard
    Name = PIA ${cli#-*} [${REGION_NAME}] wireguard tunnel
    Host = ${Endpoint%:*}
    Domain = ${WG_HOSTNAME}
    WireGuard.Address = ${Address}/24
    WireGuard.ListenPort = ${Endpoint#*:}
    $(_is_set "${DNS}" && echo "WireGuard.DNS = ${DNS}")
    WireGuard.PrivateKey = ${PrivateKey}
    WireGuard.PublicKey = ${PublicKey}
    WireGuard.AllowedIPs = ${AllowedIPs}
    WireGuard.EndpointPort = ${Endpoint#*:}
    #WireGuard.PersistentKeepalive = ${PersistentKeepalive}
	EOF
    #
    echo "OK!" #
    echo #

  # backup pia[-(user_added)].config
    cp -v /storage/.config/wireguard/pia"${cli}".config /storage/.config/wireguard/pia"${cli}${WG_HOSTNAME/#/-}".config~ #

  # determine names of VPN used by connmanctl #
    SERVICE="vpn_${Endpoint%:*}${WG_HOSTNAME/#/_}" #

  # I placed this here for interactive use of these scripts #
  # CONNMAN_CONNECT is set true by systemd #
  # AUTOCONNECT true|false from .env (default false) if run non-interactively #
  # TO CONNECT OR NOT #
# MOVED actual CONNECTION to post_up.sh #
# so we can skip this script if pia.config is still valid #

    if [[ "${CONNMAN_CONNECT}" = "true" ]] \
         ||
       [[ "${AUTOCONNECT}" = "true" ]] #
    then echo "CONNMAN service ${SERVICE}! is ready" |& #
  # Skip to ./post_up.sh #
         tee -i >(_logger ) >/dev/null # >(_pia_notify ) >/dev/null #
         #sleep 1 #

    else #
  # Connection Dialog/Monologue #
         if _is_tty #
         then echo -e "\nCONNMAN service ${SERVICE}! is ready" #
       # running interactively

              echo -n "    Do you wish to connect now([Y]es/[n]o): " #
              shopt -s nocasematch
              read -r connect #
              echo #

              if [[ "${connect}" == *"n"* ]] #
              then _print_connection_instructions #
            # don't connect
                   exit 0 #
              else echo -e "User wishes to proceed with connection\n" #
            # connect

                 # proceed with connection
                   export CONNMAN_CONNECT=true
              fi #
              shopt -u nocasematch
         else _print_connection_instructions #
       # running non-interactively, log and Gui.Notifications #
              exit 0 #
         fi #
    fi #

  # this was delayed when called interactively
  # check for conflict with systemd #
  # run deferred ./pre_up.sh #

    if _is_tty \
         &&
       [[  $(systemctl list-unit-files pia-wireguard.service) =~ able ]] #
    then #
  # run interactive with systemd service #
         case $(_service_is_active pia-wireguard) #
         in #
          # systemd service active #
            0|true)  printf "pia-wireguard service is running, continue? ([N]o/[y]es): " #
                   # stop? #

                     shopt -s nocasematch
                     read -r continue #
                     if [[ "${continue}" != *"y"* ]] #
                   # NO #
                     then echo "Goodbye" #
                          _print_connection_instructions #
                          exit 0 #
                     else # 
                   # YES #
                        # log this to systemd journal #
                          systemd-cat -t pia-wireguard.cmdline -p notice \
                                     <<< "Stopping pia-wireguard.service from the command line" #
                          systemctl stop pia-wireguard.service #
                        # stop pia-wireguard service #
                        # This runs ./shutdown.sh which should mirror ./pre_up.sh #
                        # i.e disconnecting, iptables, DNS, port_forward.sh,stops apps #
                     fi # 
                     shopt -u nocasematch
                   ;; #
            *|false) echo "pia-wireguard service is not running" #
          # sally forth #
                     export PRE_UP_RUN='cli' #
                     ./pre_up.sh #
             ;; #
         esac #

    elif _is_tty #
    then export PRE_UP_RUN='cli' #
  # interactive w/o systemd service defered run of pre_up.sh #
         ./pre_up.sh #
    fi #

    if [[ "${PRE_UP_RUN}" != 'true' ]] #
    then echo -e "Not called by systemd" |& #
         tee -i >(_logger ) >/dev/null #
  # called outside of systemd, run ./post_up.sh manually #
  # have exported PRE_UP_RUN and CONNMAN_CONNECT cli=-(user_added)|NULL #
         echo -e "calling $(pwd)/post_up.sh\n" |& #
         tee -i >(_logger ) >/dev/null #
         ./post_up.sh & #
    fi #

#############################################
    exit 0                                  #
#############################################
# USING CONNMANCTL instead
## Start the WireGuard interface.
## If something failed, stop this script.
## If you get DNS errors because you miss some packages,
## just hardcode /etc/resolv.conf to "nameserver 10.0.0.242".
#echo
#echo "Trying to create the wireguard interface..."
#wg-quick up pia || exit 1
#echo
#echo -e "${green}The WireGuard interface got created.${nc}

#At this point, internet should work via VPN.

#To disconnect the VPN, run:

#--> ${green}wg-quick down pia${nc} <--
#"
#PIA_PF=false
# This section will stop the script if PIA_PF is not set to "true".
#if [[ $PIA_PF != "true" ]]; then
  #echo "If you want to also enable port forwarding, you can start the script:"
  #echo -e "$ ${green}PIA_TOKEN=$PIA_TOKEN" \
    #"PF_GATEWAY=$WG_SERVER_IP" \
    #"PF_HOSTNAME=$WG_HOSTNAME" \
    #"./port_forwarding.sh${nc}"
  #echo
  #echo "The location used must be port forwarding enabled, or this will fail."
  #echo "Calling the ./get_region script with PIA_PF=true will provide a filtered list."
  #exit 1
#fi

#echo -ne "This script got started with ${green}PIA_PF=true${nc}.

#Starting port forwarding in "
#for i in {5..1}; do
  #echo -n "$i..."
  #sleep 1
#done
#echo
#echo

#echo -e "Starting procedure to enable port forwarding by running the following command:
#$ ${green}PIA_TOKEN=$PIA_TOKEN \\
  #PF_GATEWAY=$WG_SERVER_IP \\
  #PF_HOSTNAME=$WG_HOSTNAME \\
  #./port_forwarding.sh${nc}"

#PIA_TOKEN=$PIA_TOKEN \
  #PF_GATEWAY=$WG_SERVER_IP \
  #PF_HOSTNAME=$WG_HOSTNAME \
  #./port_forwarding.sh
