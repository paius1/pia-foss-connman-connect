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

# This function allows you to check if the required tools have been installed.
check_tool() {
  cmd=$1
  if ! command -v "$cmd" >/dev/null; then
    echo "$cmd could not be found"
    echo "Please install $cmd"
    exit 1
  fi
}
# Now we call the function to make sure we can use wg-quick, curl and jq.

# wg-quick doesn't seem to work with coreelec
#check_tool wg-quick
check_tool curl
check_tool jq

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
  "https://${WG_HOSTNAME}:1337/addKey" )"
export wireguard_json

# Check if the API returned OK and stop this script if it didn't.
if [[ $(echo "$wireguard_json" | /opt/bin/jq -r '.status') != "OK" ]]; then
  >&2 echo -e "${red}Server did not return OK. Stopping now.${nc}"
  exit 1
fi

    # For debugging
      echo "${wireguard_json}" > /tmp/wireguard_json

# CONNMAN sets up the interface ignoring wg-quick

## Multi-hop is out of the scope of this repo, but you should be able to
## get multi-hop running with both WireGuard and OpenVPN by playing with
## these scripts. Feel free to fork the project and test it out.
#echo
#echo "Trying to disable a PIA WG connection in case it exists..."
#wg-quick down pia && echo -e "${green}\nPIA WG connection disabled!${nc}"
#echo

# Create the WireGuard config based on the JSON received from the API
# In case you want this section to also add the DNS setting, please
# start the script with PIA_DNS=true.
# This uses a PersistentKeepalive of 25 seconds to keep the NAT active
# on firewalls. You can remove that line if your network does not
# require it.


if [[ $PIA_DNS == "true" ]]; then
  dnsServer=$(echo "$wireguard_json" | /opt/bin/jq -r '.dns_servers[0]')
  echo "Set up DNS to $dnsServer. Since we do not have resolvconf,"
  echo "we will just heredoc it to /etc/resolv.conf"
  echo "since connman uses any preset dns resolvers first"
  echo

    cat <<-EOF > /etc/resolv.conf
    # Generated by PIA WIREGUARD
    #search example.com
    nameserver $dnsServer
	EOF

fi

  # THIS IS WHERE WE CONNECT and since wg-quick doesn't work
  # we convert wireguard.conf to a connman config

echo -n "Trying to write /etc/wireguard/pia.conf..."
mkdir -p /opt/etc/wireguard
echo "
[Interface]
Address = $(echo "$wireguard_json" | /opt/bin/jq -r '.peer_ip')
PrivateKey = $privKey
$dnsSettingForVPN
[Peer]
PersistentKeepalive = 25
PublicKey = $(echo "$wireguard_json" | /opt/bin/jq -r '.server_key')
AllowedIPs = 0.0.0.0/0
Endpoint = ${WG_SERVER_IP}:$(echo "$wireguard_json" | /opt/bin/jq -r '.server_port')
" > /storage/.opt/etc/wireguard/pia.conf || exit 1
echo -e "${green}OK!${nc}"

  # read wireguard.conf into variables
    eval $( grep -e '^[[:alpha:]]' /opt/etc/wireguard/pia.conf | sed 's/ = /=/g')
  
  # Determine name of VPN used by CONNMAN
    SERVICE=$( sed 's/\./_/g' <<< "vpn_${Endpoint%:*}")

    # write wireguard config
    cat <<-EOF > /storage/.config/wireguard/pia.config
    [provider_wireguard]
    Type = WireGuard
    Name = WireGuard VPN Tunnel
    Host = ${Endpoint%:*}
    WireGuard.Address = ${Address}/24
    WireGuard.ListenPort = ${Endpoint#*:}
    WireGuard.PrivateKey = ${PrivateKey}
    WireGuard.PublicKey = ${PublicKey}
    WireGuard.AllowedIPs = ${AllowedIPs}
    WireGuard.EndpointPort = ${Endpoint#*:}
	EOF

    # I placed this here for interactive use of these scripts
    if [[ "${CONNMAN_CONNECT}" != "true" ]]
    then
         echo "CONNMAN service ${SERVICE}! is ready"
         echo -n "Do you wish to connect now([Y]es/[n]o): "
         read -r connect
         echo
         if echo "${connect:0:1}" | grep -iq n
         then echo "go to Settings > Coreelec > Connections to connect"
              echo ""
              echo
              exit 0
         fi
    fi

sleep 2
    if connmanctl connect "${SERVICE}"
    then echo "Connected to PIA and restoring firewall"
         iptables-restore < rules-wireguard.v4
         echo ""
    else echo -e "CONNMAN service ${SERVICE} failed!"
         exit 255
    fi

    # This section will stop the script if PIA_PF is not set to "true".
    # the command for port forwarding will be sent to /tmp/pf.log
    if [[ $PIA_PF != "true" ]]; then
      echo "If you want to also enable port forwarding, you can start the script:"
      echo "PIA_TOKEN=$PIA_TOKEN $(pwd)/pf.sh" | tee /tmp/pf.log
      echo
      echo "The location used must be port forwarding enabled, or this will fail."
      echo "Calling the ./get_region script with PIA_PF=true will provide a filtered list."
      exit 1
    fi

  # Called from command line not systemd service
    if [[ -t 0 || -p /dev/stdin ]]
    then echo -ne "This script got started with PIA_PF=true.
        and from the cli
        Starting port forwarding in "
        for i in {5..1}; do
          echo -n "$i..."
          sleep 1
        done
        echo
        echo
        
            echo "Enabling port forwarding by running: PIA_TOKEN=$PIA_TOKEN $(pwd)/pf.sh"
            
            PIA_TOKEN=$PIA_TOKEN \
              ./pf.sh &
    fi
#########
 exit 0 #
#########
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
