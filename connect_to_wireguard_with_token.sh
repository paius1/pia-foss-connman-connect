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

    export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin #

    [ -z "${kodi_user}" ] \
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

# Verify overwriting a system generated file from shell
    if #
    [[ -t 0 || -n "${SSH_TTY}" ]] \
      && \
    [[ -s /opt/etc/wireguard/pia.conf ]] #
  # Overwrite existing pia.conf running interactively #
    then printf "Wireguard configuration exists, overwrite? ([Y]es/[n]o): " #
         read -r continue #
         if grep -iq n <<< "${continue:0:1}" #
       # NO, add '(user added)' #
         then cli='(user added)' #
         fi #
    elif ! [[ -t 0 || -n "${SSH_TTY}" ]] #
  # not interactive make backup [ -v sends to log/journal ]
    then cp -v /opt/etc/wireguard/pia.conf /opt/etc/wireguard/pia.conf~
    fi #

# Create ephemeral wireguard keys, that we don't need to save to disk.
privKey=$(wg genkey | tee /opt/etc/piavpn-manual/privKey )
export privKey
pubKey=$( echo "$privKey" | wg pubkey | tee /opt/etc/piavpn-manual/pubKey )
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
         _pia_notify "Server did not return OK. Stopping now."  '10000' 'pia_off_48x48.png' #
       # added for NON_INTERACTIVE #
  exit 1
fi

  # LibreElec doesn't include the iptables_raw kernel module #
  # CONNMAN sets up the interface ignoring wg-quick #
# Create the WireGuard config based on the JSON received from the API
# In case you want this section to also add the DNS setting, please
# start the script with PIA_DNS=true.
# This uses a PersistentKeepalive of 25 seconds to keep the NAT active
# on firewalls. You can remove that line if your network does not
# require it.
if [[ $PIA_DNS == "true" ]]; then
  dnsServer=$(echo "$wireguard_json" | /opt/bin/jq -r '.dns_servers[0]')
       if [[ -t 0 || -n "${SSH_TTY}" ]] #
     # RUNNING INTERACTIVELY #
       then #
  echo #
  echo "Set up DNS to $dnsServer. Since we do not have resolvconf," #
  echo "we will rely on connman to set nameservers" #
  echo "and ensure ${dnsServer} is the first one" #
  echo
       fi #
  dnsSettingForVPN="DNS = ${dnsServer}" #
fi
echo -n "Trying to write /opt/etc/wireguard/pia${cli}.conf..." #
  # changed path #
    mkdir -p /opt/etc/wireguard #
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
" > /opt/etc/wireguard/pia"${cli}".conf || exit 1 # changed path #
echo -e "${green}OK!${nc}"
    echo #

# Notes
# LibreElec doesn't include the iptables_raw kernel module so it's not possible to set AllowedIps as 0.0.0.0/0 #
  # Since I can't get wg-quick to work #
  # Convert wireguard .conf to a connman .config #

  # read wireguard.conf into variables and export any needed by post_up.sh #
    eval "$( grep -e '^[[:alpha:]]' /opt/etc/wireguard/pia"${cli}".conf | sed 's/ = /=/g')" #
    export DNS #
unset cli
# Prevent overwriting a system generated file from shell. default adds '(user added)' to Name=
    if 
    [[ -t 0 || -n "${SSH_TTY}" ]] \
      && \
    [[ -s /storage/.config/wireguard/pia.config ]] #
  # Overwrite existing .conf running interactively #
    then printf "PIA Wireguard configuration exists, overwrite? ([N]o/[y]es): " #
         read -r continue #
         if grep -iq -v y <<< "${continue:0:1}" #
       # NO, add '(user added)' #
         then cli='(user added)' #
         fi #
    elif ! [[ -t 0 || -n "${SSH_TTY}" ]] #
  # not interactive make backup [ -v sends to log/journal ]
    then cp -v /storage/.config/wireguard/pia.config /storage/.config/wireguard/pia.config~
    fi #

  # Determine names of VPN used by connmanctl #
  # Save for use by scripts when not run in order line 398
    REGION_NAME="$(/opt/bin/jq -r '.name' /opt/etc/piavpn-manual/regionData | tee /media/paul/coreelec/storage/.config/wireguard/connman.vars )" #
    SERVICE=$( sed 's/\./_/g' <<< "vpn_${Endpoint%:*}" | tee -a /media/paul/coreelec/storage/.config/wireguard/connman.vars) #
    export SERVICE #

# Are the endpoints the same
        # Existing .confg
    # write wireguard config #
    cat <<-EOF > /storage/.config/wireguard/pia"${cli}".config
    [provider_wireguard]
    Type = WireGuard
    Name = PIA ${cli} [${REGION_NAME}] wireguard tunnel
    Host = ${Endpoint%:*}
    WireGuard.Address = ${Address}/24
    WireGuard.ListenPort = ${Endpoint#*:}
    WireGuard.DNS = ${DNS}
    WireGuard.PrivateKey = ${PrivateKey}
    WireGuard.PublicKey = ${PublicKey}
    WireGuard.AllowedIPs = ${AllowedIPs}
    WireGuard.EndpointPort = ${Endpoint#*:}
    WireGuard.PersistentKeepalive = ${PersistentKeepalive}
	EOF
    #

  # I placed this here for interactive use of these scripts #
  # CONNMAN_CONNECT is set true by systemd; AUTOCONNECT from environment #
  # AUTOCONNECT default false if run non-interactively #
  # TO CONNECT OR NOT
# MOVED actual CONNECTION to post_up.sh in case wireguard/pia.conf is unchaged #
    if 
    [[ "${CONNMAN_CONNECT}" = "true" ]] \
      || \
    [[ "${AUTOCONNECT}" = "true" ]] #
  # Skip to connmanctl connect vpn_XXX_XXX_XXX_XXX
    then _logger "CONNMAN service ${SERVICE}! is ready" #
         #_pia_notify 'Connman config for '"${REGION_NAME}"' created'
         sleep 1 #
    else #
  # Connection Dialog/Monologue #
         if [[ -t 0 || -n "${SSH_TTY}" ]] #
       # running interactively
         then echo -e "\nCONNMAN service ${SERVICE}! is ready" #
              echo -n "    Do you wish to connect now([Y]es/[n]o): " #
              read -r connect #
              echo #
              if echo "${connect:0:1}" | grep -iq n #
              then echo -e "to connect manually go to" #
                   echo -e "\tSettings > Coreelec > Connections, select WireGuard and connect" #
                   echo -e "\t    This may not set DNS and" #
                   echo -e "\t    WILL NOT set iptables killswitch!?" #
                   echo -e "\tiptables-restore $(pwd)/rules-wireguard.v4     WILL!" #
                   echo #
                        echo  -e "\tTo (re)enable port forwarding run\n" 
                        echo -e "    PIA_TOKEN=$PIA_TOKEN PF_GATEWAY=$WG_SERVER_IP PF_HOSTNAME=$WG_HOSTNAME $(pwd)/port_forwarding.sh" #
                   if [[ "${PIA_PF}" != 'true' ]] #
                 # add caveat
                   then #
                        echo #
                        echo -e "\tThe location used must be port forwarding enabled, or this will fail." #
                        echo -e "\tCall PIA_PF=true $(pwd)/get_region for a filtered list." #
                   fi #
                        echo -e "\n\tport_forwading.sh must be left running to maintain the port" #
                        echo -e "\tIt WILL TIE UP A CONSOLE unless run in the background" #
                        echo #
                   exit 0 #
              else echo -e "User wishes to proceed with connection\n" #
              fi #
         else #
       # RUNNING NON-INTERACTIVELY log and Gui.Notifications #
            # two lines that require scrolling really mess up estuary etc. #
            # and some skins don't scroll and limit the number of lines #
              if [[ "${PRE_UP_RUN}y" != 'true' ]] #
            # No systemd service installed #
              then #
                   _logger 'Saved configuration for '"${REGION_NAME}"' '#
                   _logger "Goto Settings>Coreelec>Connections" #
                   _logger "This precludes port forwarding and setting a safe firewall" #
                   _logger "This precludes port forwarding and setting a safe firewall" #
                   _logger "Set CONNMAN_CONNECT=true to avoid this" #
              fi #
              _pia_notify 'Saved configuration for '"${REGION_NAME}"' '; sleep 4 #
              _pia_notify "Goto Settings>Coreelec>Connections" 10000; sleep 10 #
              _pia_notify "This precludes port forwarding and setting a safe firewall" ; sleep 5 #
              _pia_notify "This precludes port forwarding and setting a safe firewall" ; sleep 5 #
              _pia_notify "Set CONNMAN_CONNECT=true to avoid this" 10000 #
              exit 0 #
         fi #
    fi #

  # Check for conflict between interactive run and systemd #
    if  #
    [[ -t 0 || -n "${SSH_TTY}" ]] \
      && \
    [[ "$( wc -l < <(systemctl list-unit-files pia-wireguard.service))" -gt 3 ]] #
  # Running interactively with systemd service #
    then SERVICE_STATE="$(systemctl is-active  pia-wireguard.service)" #
         if [[ "${SERVICE_STATE}" =~ ^a ]] #
       # Service is running #
         then printf "PIA Wireguard running as a service, continue? ([N]o/[y]es): " #
              read -r continue #

              grep -iq -v y <<< "${continue:0:1}" \
                       && { echo "Goodbye"; exit 0; } #
       # YES, Send a message to systemd journal regarding this #
         systemd-cat -t pia-wireguard.cmdline -p warning <<< "Stopping pia-wireguard.service from the command line" #
       # Stop pia-wireguard service #
       # This runs ./shutdown.sh which should mirror ./pre_up.sh #
       # i.e disconnecting, iptables, DNS, port_forward.sh,stops apps #
         systemctl stop pia-wireguard.service #
         else echo "pia-wireguard service is ${SERVICE_STATE}" #
       # NO, run previously skipped pre_up.sh
              ./pre_up.sh #
         fi #
    elif [[ -t 0 || -n "${SSH_TTY}" ]] #
  # interactive w/o systemd service  defered run of pre_up.sh #
    then export PRE_UP_RUN='cli' #
         ./pre_up.sh #
    fi #

  # Save for use by scripts when not run in order
    echo -e "SERVICE=\"${SERVICE}\"\n REGION_NAME=\"${REGION_NAME}\"" > /storage/.config/wireguard/connman.vars

  # Moving port forwarding to post_up.sh loses all of these variables
    echo " PIA_PF=$PIA_PF PIA_TOKEN=$PIA_TOKEN PF_GATEWAY=$WG_SERVER_IP PF_HOSTNAME=$WG_HOSTNAME $(pwd)/port_forwarding.sh" | tee /opt/etc/piavpn-manual/port_forward.cmd #
  # reusability
    echo "WG_SERVER_IP=\"$PF_GATEWAY\"
WG_HOSTNAME=\"$PF_HOSTNAME\"" | tee -a /opt/etc/piavpn-manual/port_forward.cmd #

  # if called outside of systemd, then run ./post_up.sh manually #
    if [[ "${PRE_UP_RUN}" != 'true' ]] #
    then echo -e "Not called by systemd" #
         echo -e "calling $(pwd)/post_up.sh\n" #
         ./post_up.sh > /dev/null & #
    fi #
#############################################
 exit 0                                     #
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
