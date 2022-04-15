#!/opt/bin/bash
#    v 0.0.1, c plgroves gmail 2022
#    SCRIPTNAME 
#        runs after pia-wireguard service is up
#        starts things that are dependent on vpn
#         e.g. port forwarding and transmission
#        
####
# 
    _Usage() {
         sed >&2 -n "1d; /^###/q; /^#/!q; s/^#*//; s/^ //; 
                     s/SCRIPTNAME/${BASH_SOURCE##*/}/; p" \
                    "${BASH_SOURCE%/*}/${BASH_SOURCE##*/}"
         exit 1; }
    [[ "$1" =~ ^[-hH] ]] && _Usage "$@"

    function logger() {
        local message="${1}"; local source="${2:-${BASH_SOURCE}}"; local log="${3:-$LOG}"
        local tab spaces 
        tab="${TAB:-100}"
        IFS="" spaces="$(printf "%$((tab*2))s")"
        printf %s:[%s]:%.$((${tab}-${#source}))s%s%s  "$(date)" "$(cut -d- -f2- <<< "${source##*/}") " "${spaces} " "${message}" $'\n'| tee -a "${log}"
}

    log='/dev/null'
    LOG="${1:-${log}}"
    bash_source="${#BASH_SOURCE}"; export TAB=$((bash_source+1))

  # PIA's scripts are set to a relative path
    cd "${0%/*}" || exit 255

  # get PIA_PF
    source .env 2>/dev/null

    if [[ $PIA_PF != "true" ]]; then
      echo "If you want to also enable port forwarding, you can start the script:"
      echo "PIA_TOKEN=$PIA_TOKEN $(pwd)/pf.sh" | tee /tmp/pf.log
      echo
      echo "The location used must be port forwarding enabled, or this will fail."
      echo "Calling the ./get_region script with PIA_PF=true will provide a filtered list."
      exit 1
    fi

    echo -n "This script got started with PIA_PF=true.
    
    Starting port forwarding in "
    for i in {5..1}; do
      echo -n "$i..."
      sleep 1
    done
    echo
    echo

  # not called by pia-foss manual-connections scripts so have to pass with file
    export PIA_TOKEN="${PIA_TOKEN:-$(head -1 /opt/etc/piavpn-manual/token)}"
  # Couldn't get PIA's working so using modifed one from
  # https://github.com/thrnz/docker-wireguard-pia/blob/master/extra/pf.sh
    ./pf.sh > /tmp/pf.log &

exit 0
