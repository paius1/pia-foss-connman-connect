#!/opt/bin/bash
#    v 0.0.1,
# 
#    SCRIPTNAME 
#        installs entware and required dependencies for
#        pia-foss-connman-connect
#        
####
# c plgroves gmail 2022

  _Usage() {
       sed >&2 -n "1d; /^###/q; /^#/!q; s/^#*//; s/^ //; 
                   s/SCRIPTNAME/${BASH_SOURCE##*/}/; p" \
                  "${BASH_SOURCE%/*}/${BASH_SOURCE##*/}"
       exit 1; }
  [[ "$1" =~ ^[-hH] ]] && _Usage "$@"

  # PIA's scripts are set to a relative path
    cd "${0%/*}"
  
  # check for entware and intalled packages
    if [ -f /storage/.opt/bin/opkg ]
    then echo -e "\nentware is available\n"
    else echo -e "\n please install entware\n  https://discourse.coreelec.org/t/what-is-entware-and-how-to-install-uninstall-it/1149"
         echo -n "Do you want to install entware now ([Y]es/[n]o): "
         read -r install
         echo
         if echo "${install:0:1}" | grep -iq n
         then exit 1
         fi
         installentware || exit 255
    fi

  # check for required entware packages or install
    install="/opt/bin/opkg install "
    Packages=('bash' 'coreutils-sort' 'curl' 'date' 'jq' 'grep' 'iptables' 'sed' 'wireguard-tools'  )
    mapfile -t Installed < <(/opt/bin/opkg list-installed | awk '{print $1}')
    for package in "${Packages[@]}"; do
     if [[  " ${Installed[@]} " =~ " $package " ]]
     then echo -ne " found ${package} from entware          \r"; sleep 0.5
     else echo -e " ${package} not found ... installing\n"
          "${install} $package" >/dev/null
          echo
     fi
    done
    echo -e "\r All packages installed            \n"
