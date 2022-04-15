#!/opt/bin/bash

# Bash script for port-forwarding on the PIA 'next-gen' network.
# started with https://github.com/thrnz/docker-wireguard-pia/blob/master/extra/pf.sh
# and hacked this together
# Requires curl jq
#
# For port forwarding on the next-gen network, we need a valid PIA auth token (see get_token.sh) and to know the address to send API requests to.
#
# With Wireguard, the PIA app uses the 'server_vip' address found in the 'addKey' response (eg 10.x.x.1), although 'server_ip' also appears to work.
# With OpenVPN, the PIA app uses the gateway IP (also 10.x.x.1)
#
# Optionally, if we know the common name of the server we're connected to we can verify our HTTPS requests.
#
# Previously, PIA port forwarding was done with a single request when the VPN came up.
# Now we need to 'rebind' every 15 mins in order to keep the port open/alive.
#
# This script has been tested with Wireguard and briefly with OpenVPN
#
# based on what was found in the source code to their desktop app (v.2.2.0):
# https://github.com/pia-foss/desktop/blob/2.2.0/daemon/src/portforwardrequest.cpp
# Use at your own risk!
# modified for coreELEC/connman plgroves gmail 2022

    # PIA's scripts are set to a relative path
      cd "${0%/*}"

    PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin

  # where to store the port number for later usage
    portfile='/tmp/port.dat'

  # stop any previous instances of pf.sh
    pids=($(pidof pf.sh))
    mypid=$$

    if [ "${#pids[@]}" -gt 1 ]
    then # remove this instance from pids
         echo "pf.sh is already running, will stop"
         for i in ${!pids[@]}
         do
            if [ "${pids[$i]}" == "$mypid" ]
            then unset pids[$i]
            fi
         done
         echo "${pids[@]}" | xargs kill >/dev/null 2>&1
    fi

# An error with no recovery logic occured
fatal_error () {
  cleanup
  echo "$(date): Fatal error"
  echo "$(date): Attempting Restarting"
  PIA_TOKEN="${PIA_TOKEN}" "$(pwd)/${BASH_SOURCE##*/}" >> /tmp/pf.log &
  exit 1
}

cleanup(){
  [ "$cacert_istemp" == "1" ] && [ -w "$cacert" ] && rm "$cacert"
}

# Handle shutdown behavior
finish () {
  cleanup
  echo "$(date): Port forward rebinding stopped. The port will likely close soon."
  exit 0
}
trap finish SIGTERM SIGINT SIGQUIT

  # We don't use any error handling or retry logic beyond what curl provides
    curl_max_time=15
    curl_retry=5
    curl_retry_delay=15

  # Check if the mandatory environment variables are set.
    if [[ ! $PIA_TOKEN ]]; then
      echo This script requires:
      echo PIA_TOKEN   - the token you used to connect to the vpn services
      echo
      echo An easy solution is to just run
      echo 'PIA_TOKEN=$(head -1 /opt/etc/piavpn-manual/token)'
      echo then PIA_TOKEN=\${PIA_TOKEN} ${BASH_SOURCE}
      echo 
    exit 1
    fi

bind_port () {
  pf_bind=$(curl --get --silent --show-error \
      --retry $curl_retry --retry-delay $curl_retry_delay --max-time $curl_max_time \
      --data-urlencode "payload=$pf_payload" \
      --data-urlencode "signature=$pf_getsignature" \
      "${verify}" \
      "https://$pf_host:19999/bindPort")
  if [ "$(echo "${pf_bind}" | /opt/bin/jq -r .status)" != "OK" ]; then
    echo "$(date): bindPort error"
    echo "${pf_bind}"
    fatal_error
  fi
}

get_sig () {
  pf_getsig=$(curl --get --silent --show-error \
    --retry $curl_retry --retry-delay $curl_retry_delay --max-time $curl_max_time \
    --data-urlencode "token=${PIA_TOKEN}" \
    "${verify}" \
    "https://$pf_host:19999/getSignature")
  if [ "$(echo "${pf_getsig}" | /opt/bin/jq -r .status)" != "OK" ]; then
    echo "$(date): getSignature error"
    echo "${pf_getsig}"
    fatal_error
  fi
  pf_payload=$(echo "${pf_getsig}" | /opt/bin/jq -r .payload)
  pf_getsignature=$(echo "${pf_getsig}" | /opt/bin/jq -r .signature)
  pf_port=$(echo "${pf_payload}" | base64 -d | /opt/bin/jq -r .port)
  pf_token_expiry_raw=$(echo "${pf_payload}" | base64 -d | /opt/bin/jq -r .expires_at)
  # Coreutils date doesn't need format specified (-D), whereas BusyBox does
  if date --help 2>&1 /dev/null | grep -i 'busybox' > /dev/null; then
    pf_token_expiry=$(date -D %Y-%m-%dT%H:%M:%S --date="$pf_token_expiry_raw" +%s)
  else
    pf_token_expiry=$(date --date="$pf_token_expiry_raw" +%s)
  fi
}

        function logger() {
            local message="${1}"; local source="${2:-${BASH_SOURCE}}"; local log="${3:-$LOG}"
            local tab spaces 
            tab="${TAB:-100}"
            IFS="" spaces="$(printf "%$((tab*2))s")"
            printf %s:[%s]:%.$((${tab}-${#source}))s%s%s  "$(date)" "$(cut -d- -f2- <<< "${source##*/}") " "${spaces} " "${message}" $'\n'| tee -a "${log}"
}

    log='/tmp/pf.log'
    LOG="${1:-${log}}"
    bash_source="${#BASH_SOURCE}"; export TAB=$((bash_source+1))

# Rebind every 15 mins (same as desktop app)
pf_bindinterval=$(( 15 * 60))
# Get a new token when the current one has less than this remaining
# Defaults to 7 days (same as desktop app)
pf_minreuse=$(( 60 * 60 * 24 * 7 ))

pf_remaining=0
pf_firstrun=1

[ -z $PIA_TOKEN ] && { PIA_TOKEN="$(head -1 /opt/etc/piavpn-manual/token)";
                       logger "had to set PIA_TOKEN!!!!!!!!!!!!!!!"; }
## Minimum args needed to run
#if [ -z "$tokenfile" ]; then
  #usage && exit 0
#fi

# Hacky way to try to automatically get the API IP: use the first hop of a traceroute.
# This seems to work for both Wireguard and OpenVPN.
# Ideally we'd have been provided a cn, in case we 'guess' the wrong IP.
# Must be a better way to do this.
  vpn_ip=$( /opt/sbin/traceroute -4 -m 1 privateinternetaccess.com | tail -n 1 | awk '{print $2}')
  # Very basic sanity check - make sure it matches 10.x.x.1
  if ! echo "$vpn_ip" | grep '10\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.1' > /dev/null; then
    echo "$(date): Automatically getting API IP failed."
    fatal_error
  fi
  echo "$(date): Using $vpn_ip as API endpoint"
  # For simplicity, use '--insecure' by default, though show a warning
  echo "$(date): API requests will be insecure until I figure out otherwise. "
  verify="--insecure"
  pf_host="$vpn_ip"

# If are not using a cn, and cannot verify using the PIA ca cert
# this is insecure

# Main loop
while true; do
  pf_remaining=$((  pf_token_expiry - $(date +%s) ))
  # Get a new pf token as the previous one will expire soon
  if [ $pf_remaining -lt $pf_minreuse ]; then
    if [ $pf_firstrun -ne 1 ]; then
      logger "$(date): PF token will expire soon. Getting new one."
    else
      logger "$(date): Getting PF token"
      pf_firstrun=0
    fi
    get_sig
    logger "$(date): Obtained PF token. Expires at $pf_token_expiry_raw"
    bind_port
    logger "$(date): Server accepted PF bind"
    logger "$(date): Forwarding on port=\"${pf_port}\""
  # send Forwarding port to journal  
    >&2 echo "Forwarding on port=\"${pf_port}\""
    logger "$(date): Rebind interval: $pf_bindinterval seconds"
    # Dump port here if requested
    [ -n "$portfile" ] && echo "$(date): Port dumped to $portfile" && echo "${pf_port}" > "$portfile"

  # add port to iptables
    echo "$(date): adding peer port ${pf_port} to firewall"
    iptables -I INPUT -p tcp --dport "${pf_port}" -j ACCEPT

  fi
  sleep $pf_bindinterval &
  wait $!
  bind_port
done
