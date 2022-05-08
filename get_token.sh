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
# hard coded/changed paths
# reuse token within 24 hours
# error messages to display or terminal

  # PIA's scripts are set to a relative path #
    cd "${0%/*}" || exit 255 #

    export PATH=/opt/bin:/opt/sbin:"${PATH}" #

  # Gui Notifications #
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
# hard coded path #
    check_tool /opt/bin/curl #
    check_tool /opt/bin/jq #

# This function creates a timestamp, to use for setting $TOKEN_EXPIRATION
timeout_timestamp() {
  date +"%c" --date='1 day' # Timestamp 24 hours
}

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

# Only allow script to run as root
if (( EUID != 0 )); then
  echo -e "${red}This script needs to be run as root. Try again with 'sudo $0'${nc}"
  exit 1
fi
  # changed path #
    mkdir -p /opt/etc/piavpn-manual #

if [[ -z $PIA_USER || -z $PIA_PASS ]]; then
  echo "If you want this script to automatically get a token from the Meta"
  echo "service, please add the variables PIA_USER and PIA_PASS. Example:"
  echo "$ PIA_USER=p0123456 PIA_PASS=xxx ./get_token.sh"
  exit 1
fi

  # check for existing token #
  # they are good for 24 hours! #
    if [[ -s /opt/etc/piavpn-manual/token ]] #
    then #
  # existing tokenFile #
         # https://stackoverflow.com/users/2318662/tharrrk #
         m2n() { printf '%02d' $((-10+$(sed 's/./\U&/g;y/ABCEGLNOPRTUVY/60AC765A77ABB9/;s/./+0x&/g'<<<${1#?}) ));} #

              mapfile -t tokenFile <  /opt/etc/piavpn-manual/token
            # 2 steps with builtins vs. awk
              month="${tokenFile[1]#* }"
               month="${month%% *}"
                month="$(m2n "${month}")"
              expiry_iso="$(awk '{printf "%d-%02d-%02dT%s", $NF,$2,$3,$4}' < <( awk -v month="${month}" '$2=month' <<< "${tokenFile[1]}"))"

         if (( $(date -d "+30 min" +%s) < $(date -d "${expiry_iso}" +%s) )) #
         then echo "Previous token OK!" #
       # less than 24hrs old #
              exit 0 #
         fi #
    else echo "token expired retrieving a new one" #
  # day old, refresh
    fi #

echo -n "Checking login credentials..."

generateTokenResponse=$(curl -s -u "$PIA_USER:$PIA_PASS" \
  "https://www.privateinternetaccess.com/gtoken/generateToken")

if [[ $(echo "$generateTokenResponse" | /opt/bin/jq -r '.status') != "OK" ]]; then #
     if _is_tty #
     then #
  echo
  echo
  echo -e "${red}Could not authenticate with the login credentials provided!${nc}"
  echo
     else #
          _pia_notify "Could not authenticate " '15000' & #
     fi #
  exit 255 #
fi

echo -e "${green}OK!"
echo
token=$(echo "$generateTokenResponse" | /opt/bin/jq -r '.token') #
tokenExpiration=$(timeout_timestamp)
tokenLocation=/opt/etc/piavpn-manual/token

     if _is_tty #
   # Running interactively #
     then #
          echo -e "PIA_TOKEN=$token${nc}"
          echo #
          echo "This token will expire in 24 hours, on $tokenExpiration." #
          echo #
     fi #
          echo "$token" > "$tokenLocation" || exit 1 #
          echo "$tokenExpiration" >> "$tokenLocation" #
