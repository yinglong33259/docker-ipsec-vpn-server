#!/bin/bash
#
# Agent sh report vpn and vpn connection status
#
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

while [ true ]; do
/bin/sleep 2
curl --location --request POST 'http://100.73.142.78:5547/api/objs/VpnConnectionStatusReport' \
--header 'NERV-TOKEN: 72e9ff31a36f9694601d2ec77a8007f7' \
--header 'Content-Type: text/plain' \
--data-raw '{
    "name":"conn2",
    "projectId":1,
    "vpnGatewayId":24,
    "localSubnet":"100.73.142.0/24",
    "remoteGateway":"10.65.225.113",
    "remoteSubnet":"10.0.0.0/8",
    "loginUserID":1,
    "psk":"huangxstest21"
}'
done