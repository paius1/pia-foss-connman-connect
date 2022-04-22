#!/opt/bin/bash
#    v 0.0.1, c plgroves gmail 2022
#    SCRIPTNAME called by PATH/connect_to_wireguard_with_token.sh
#        
#        put commands here to run after vpn is up
#        
#         e.g. transmission
#        
####
# 
    _Usage() {
         sed >&2 -n "1d; /^###/q; /^#/!q; s/^#*//; s/^ //; 
                     s!PATH!$(pwd)!; s/SCRIPTNAME/${BASH_SOURCE##*/}/; p" \
                    "${BASH_SOURCE%/*}/${BASH_SOURCE##*/}"
         exit 1; }
    [[ "$1" =~ ^[-hH] ]] && _Usage "$@"

  # PIA's scripts are set to a relative path #
    cd "${0%/*}" #

    export PATH=/opt/bin:/opt/sbin:/usr/bin:/usr/sbin #

    function logger() {
        local message="${1}"; local source="${2:-${BASH_SOURCE}}"; local log="${3:-$LOG}"
        local tab spaces 
        tab="${TAB:-100}"
        IFS="" spaces="$(printf "%$((tab*2))s")"
        printf %s:[%s]:%.$((${tab}-${#source}))s%s%s  "$(date)" "$(cut -d- -f2- <<< "${source##*/}") " "${spaces} " "${message}" $'\n'| tee -a "${log}"
}

    log="${LOG:=/dev/null}"
    LOG="${1:-${log}}" # export LOG to environment to monitor these scripts
    bash_source="${#BASH_SOURCE}"; export TAB=$((bash_source+1))

  # PIA's scripts are set to a relative path
    cd "${0%/*}" || exit 255
    logger "Place any desired commands  after this line"

exit 0
