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

# DEBUGGING #
# shellcheck source=/media/paul/coreelec/storage/sources/pia-wireguard/kodi_assets/functions
    [ -z "${kodi_user}" ] \
    && source ./kodi_assets/functions #

    if [[ "${PRE_UP_RUN}y" != 'true' ]] #
    then >&2 _logger "Finishing up ..."; fi

  # Add any applications to start after this

exit 0
