# Manual PIA VPN Connections for Connman/coreELEC

This repository take the scripts from https://github.com/pia-foss/manual-connections (slightly modified) and uses them to create a valid connman vpn config file for use with coreelec  
  
  With entware wireguard tools I tried  
  &ensp;wg-quick returns:  
  ```
  /opt/bin/wg-quick: line 32: resolvconf: command not found  
  ```
  &ensp;&ensp;remove DNS =  
  ```
  iptables-restore v1.8.7 (legacy): iptables-restore: unable to initialize table 'raw'  
  ```
  &ensp;&ensp;AllowedIPs = 0.0.0.0/1, 128.0.0.0/1  
  &ensp;can't even ping 8.8.8.8  
  
__TL/DR__:  

```
  git clone https://github.com/pia-foss/manual-connections.git
  cd pia-foss-connman-connect
```
  
To install entware and required dependencies run:
  
```
  ./entware-installer.sh
```
  
then
  
```
  ./run_setup.sh
```
  
  and follow the prompts.
  
  You should end up with a pia.config file in /storage/.config/wireguard/pia.config,
  and can connect by going to Settings >CoreELEC >Connections



# Running with systemd
Included is a systemd unit file to automate a VPN connection

to run as a service you need to:

#### &emsp;Create a:
&emsp;&ensp;/path/to/these/scripts/.env file  
&emsp;&emsp;&ensp;The original pia-foss manual scripts run interactively, so you need to pre-define variables  
 
#### &emsp;minimum .env file
               PIA_USER=pXXXXXXX
               PIA_PASS=p45sw0rdxx
               AUTOCONNECT='false' # if set 'true' PREFERRED_REGION is ignored
                      # OR         # and the script must run thru all available servers
                                   # and takes a long... long... time
               PREFERRED_REGION='aus_perth'
                                # run PIA_PF='true|false' /path/to/scripts/get_region.sh
                                # for valid options
#### &emsp;optional: some are not part of pia-foss, and must be exported
               PIA_PF='true|false'    (default false)
               PIA_DNS='true|false'   (default true)
               #export CONNMAN_CONNECT='true' # overcomes AUTOCONNECT's limitation,
                                              # and is set true by systemd
               #export MY_FIREWALL=/path/to/normal/iptables-save.file
               #export WG_FIREWALL=/path/to/wireguard/iptables-save.file
               
  
####  &emsp;Edit:
  
&emsp;&emsp;pia-wireguard.service file &ensp;&ensp;&ensp;&ensp;&ensp;Change **/path/to/scripts** to actual path  
  
&emsp;&emsp;pre_up.sh&emsp;&emsp;&emsp;add any vpn dependent applications  
&emsp;&emsp;post_up.sh&nbsp;&emsp;&emsp; you need to start/stop,  
&emsp;&emsp;shutdown.sh&nbsp;&emsp;&ensp;e.g. transmission (anyone)  





####   &emsp;Copy:
&emsp;&emsp;pia-wireguard.service to /storage/.config/system.d/  
####   &emsp;Run:

```
    systemctl daemon-reload
    systemctl enable pia-wireguard.service
    systemctl start pia-wireguard.service
    systemctl status pia-wireguard.service
    journactl -f -u pia-wireguard.service

```
#  To run from kodi Favourites:
   from pia-foss-connman-connect/kodi_assets/  
&emsp;&emsp;copy the xml in add_to_favourites.xml to /storage/.kodi/userdate/favourites.xml  
&emsp;&emsp;change the paths to the scripts and thumbnails i.e. .png files  
&emsp;&emsp;set kodi user, password, host, and port in kodi_assets/functions  

&ensp;reload kodi,  
```
  systemctl restart kodi
```
  
&emsp;&emsp;&emsp;and enjoy.
  
  
  
  
---
FROM PIA-FOSS MANUAL-CONNECTIONS:

The scripts were written so that they are easy to read and to modify. The code also has a lot of comments, so that you find all the information you might need. We hope you will enjoy forking the repo and customizing the scripts for your setup!

## Table of Contents

- [Dependencies](#dependencies)
- [Disclaimers](#disclaimers)
- [Confirmed distributions](#confirmed-distributions)
- [3rd Party Repositories](#3rd-party-repositories)
- [PIA Port Forwarding](#pia-port-forwarding)
- [Automated setup](#automated-setup)
- [Manual PF testing](#manual-pf-testing)
- [Thanks](#thanks)
- [License](#license)

## Dependencies

In order for the scripts to work (probably even if you do a manual setup), you will need the following packages:
 * `curl`
 * `jq`
 * `connmanctrl`

## Disclaimers

 * Port Forwarding is disabled on server-side in the United States.
 * These scripts do not enforce IPv6 or DNS settings, so that you have the freedom to configure your setup the way you desire it to work. This means you should have good understanding of VPN and cybersecurity in order to properly configure your setup.
 * For battle-tested security, please use the official PIA App, as it was designed to protect you in all scenarios.
 * This repo is really fresh at this moment, so please take into consideration the fact that you will probably be one of the first users that use the scripts.
 * Though we support research of open source technologies, we can not provide official support for all FOSS platforms, as there are simply too many platforms (which is a good thing). That is why we link 3rd Party repos in this README. We can not guarantee the quality of the code in the 3rd Party Repos, so use them only if you understand the risks.

## PIA Port Forwarding

The PIA Port Forwarding service (a.k.a. PF) allows you run services on your own devices, and expose them to the internet by using the PIA VPN Network. The easiest way to set this up is by using a native PIA application. In case you require port forwarding on native clients, please follow this documentation in order to enable port forwarding for your VPN connection.

This service can be used only AFTER establishing a VPN connection.

## Automated Setup

In order to help you use VPN services and PF on any device, we have prepared a few bash scripts that should help you through the process of setting everything up. The scripts also contain a lot of comments, just in case you require detailed information regarding how the technology works. The functionality is controlled via environment variables, so that you have an easy time automating your setup.

The easiest way to trigger a fully automated connection is by running this oneliner:
```
sudo VPN_PROTOCOL=wireguard DISABLE_IPV6="no" AUTOCONNECT=true PIA_PF=false PIA_USER=p0123456 PIA_PASS=xxxxxxxx ./run_setup.sh
```

Here is a list of scripts you could find useful:
 * [Prompt based connection](run_setup.sh): This script allows connections with a one-line call, or will prompt for any missing or invalid variables. Variables available for one-line calls include:
   * `PIA_USER` - your PIA username
   * `PIA_PASS` - your PIA password
   * `PIA_DNS` - true/false
   * `PIA_PF` - true/false
   * `MAX_LATENCY` - numeric value, in seconds
   * `AUTOCONNECT` - true/false; this will test for and select the server with the lowest latency, it will override PREFERRED_REGION
   * `PREFERRED_REGION` - the region ID for a PIA server
   * `VPN_PROTOCOL` - wireguard or openvpn; openvpn will default to openvpn_udp_standard, but can also specify openvpn_tcp/udp_standad/strong
   * `DISABLE_IPV6` - yes/no
 * [Get region details](get_region.sh): This script will provide server details, validate `PREFERRED_REGION` input, and can determine the lowest latency location. The script can also trigger VPN connections, if you specify `VPN_PROTOCOL=wireguard` or `VPN_PROTOCOL=openvpn`; doing so requires a token. This script can reference `get_token.sh` with use of `PIA_USER` and `PIA_PASS`. If called without specifying `PREFERRED_REGION` this script writes a list of servers within lower than `MAX_LATENCY` to a `/opt/piavpn-manual/latencyList` for reference.
 * [Get a token](get_token.sh): This script allows you to get an authentication token with a valid 'PIA_USER' and 'PIA_PASS'. It will write the token and its expiration date to `/opt/piavpn-manual/token` for reference.
 * [Connect to WireGuard](connect_to_wireguard_with_token.sh): This script allows you to connect to the VPN server via WireGuard.
 * [Enable Port Forwarding](pf.sh): Enables you to add Port Forwarding to an existing VPN connection. Adding the environment variable `PIA_PF=true` to any of the previous scripts will also trigger this script.

## Thanks
Private Internet Access for making a cli interface available

A big special thanks to [faireOwl](https://github.com/faireOwl) for his contributions to the pia-foss repository.  
  
https://github.com/thrnz/docker-wireguard-pia/blob/master/extra/pf.sh  
https://github.com/triffid/pia-wg/blob/master/pia-portforward.sh  
&emsp; for bind_port_response payload_and_signature
  
## License
This project is licensed under the [MIT (Expat) license](https://choosealicense.com/licenses/mit/), which can be found [here](/LICENSE).
