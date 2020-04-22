#!/bin/bash
#
# Docker script to configure and start an IPsec VPN server
#
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exiterr()  { echo "Error: $1" >&2; exit 1; }
nospaces() { printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
onespace() { printf '%s' "$1" | tr -s ' '; }
noquotes() { printf '%s' "$1" | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"; }
noquotes2() { printf '%s' "$1" | sed -e 's/" "/ /g' -e "s/' '/ /g"; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

if [ ! -f "/.dockerenv" ]; then
  exiterr "This script ONLY runs in a Docker container."
fi

if ip link add dummy0 type dummy 2>&1 | grep -q "not permitted"; then
cat 1>&2 <<'EOF'
Error: This Docker image must be run in privileged mode.
EOF
  exit 1
fi
ip link delete dummy0 >/dev/null 2>&1

mkdir -p /opt/src
mkdir /opt/src/bak
chmod -R 777 /opt/src/bak

#get all env paramaters
IPSEC_VIRTUAL_PRIVATE=$(cat /opt/src/nerv/IPSEC_VIRTUAL_PRIVATE)
VPN_PUBLIC_IP=$(cat /opt/src/nerv/VPN_PUBLIC_IP)
XL2TPD_IP_NET=$(cat /opt/src/nerv/XL2TPD_IP_NET)
XL2TPD_IP_RANGE=$(cat /opt/src/nerv/XL2TPD_IP_RANGE)
XL2TPD_LOCAL_IP=$(cat /opt/src/nerv/XL2TPD_LOCAL_IP)
XL2TPD_FORWARD_NIC=$(cat /opt/src/nerv/XL2TPD_FORWARD_NIC)
REPORTER_INTERVAL=$(cat /opt/src/nerv/REPORTER_INTERVAL)
REPORTER_ADDR=$(cat /opt/src/nerv/REPORTER_ADDR)
REPORTER_TOKEN=$(cat /opt/src/nerv/REPORTER_TOKEN)
VPN_IPSEC_CONNS=$(cat /opt/src/nerv/VPN_IPSEC_CONNS)
VPN_KUBE_UUID=$(cat /opt/src/nerv/VPN_KUBE_UUID)
cat <<EOF
================================================
IPsec VPN server is ready to start, parameter details:
IPSEC_VIRTUAL_PRIVATE : $IPSEC_VIRTUAL_PRIVATE
VPN_PUBLIC_IP : $VPN_PUBLIC_IP
XL2TPD_IP_NET : $XL2TPD_IP_NET
XL2TPD_IP_RANGE : $XL2TPD_IP_RANGE
XL2TPD_LOCAL_IP : $XL2TPD_LOCAL_IP
XL2TPD_FORWARD_NIC : $XL2TPD_FORWARD_NIC
REPORTER_INTERVAL : $REPORTER_INTERVAL
REPORTER_ADDR : $REPORTER_ADDR
REPORTER_TOKEN : $REPORTER_TOKEN
VPN_IPSEC_CONNS : $VPN_IPSEC_CONNS
VPN_KUBE_UUID : $VPN_KUBE_UUID
EOF

echo 'Trying to auto discover IP of this server...'
# manually define the public IP as variable 'VPN_PUBLIC_IP'.
PUBLIC_IP=${VPN_PUBLIC_IP:-''}

check_ip "$PUBLIC_IP" || exiterr "Define 'VPN_PUBLIC_IP' error."

VIRTUAL_PRIVATE=${IPSEC_VIRTUAL_PRIVATE:-'%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12'}
L2TP_NET=${XL2TPD_IP_NET:-'52.0.99.0/24'}
L2TP_LOCAL=${XL2TPD_LOCAL_IP:-'52.0.99.9'}
L2TP_POOL=${XL2TPD_IP_RANGE:-'52.0.99.10-52.0.99.200'}
L2TP_FORWARD_NIC=${XL2TPD_FORWARD_NIC:-'"eth+"'}

case $VPN_SHA2_TRUNCBUG in
  [yY][eE][sS])
    SHA2_TRUNCBUG=yes
    ;;
  *)
    SHA2_TRUNCBUG=no
    ;;
esac

# Create IPsec (Libreswan) config
cat > /etc/ipsec.conf <<EOF
config setup
  virtual-private=%v4:!$L2TP_NET
  protostack=netkey
  interfaces=%defaultroute
  uniqueids=yes
  strictcrlpolicy=no
  logfile=/var/log/pluto.log
EOF

# Specify default IPsec PSK
echo "#ipsec psk config" >> /etc/ipsec.secrets

# Create xl2tpd config
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
listen-addr = $PUBLIC_IP
port = 1701
ipsec saref = yes
auth file = /etc/ppp/chap-secrets

[lns default]
ip range = $L2TP_POOL
local ip = $L2TP_LOCAL
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# Set xl2tpd options
cat > /etc/ppp/options.xl2tpd <<EOF
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
crtscts
idle 1800
mtu 1410
mru 1410
nodefaultroute
debug
lock
proxyarp
connect-delay 5000
require-mschap-v2
EOF

# Create VPN credentials
# cat > /etc/ppp/chap-secrets <<EOF
# "$VPN_DEFAULT_USER" * "$VPN_DEFAULT_PASSWORD" *
# EOF

# Update sysctl settings
SYST='/sbin/sysctl -e -q -w'
if [ "$(getconf LONG_BIT)" = "64" ]; then
  SHM_MAX=68719476736
  SHM_ALL=4294967296
else
  SHM_MAX=4294967295
  SHM_ALL=268435456
fi
$SYST kernel.msgmnb=65536
$SYST kernel.msgmax=65536
$SYST kernel.shmmax=$SHM_MAX
$SYST kernel.shmall=$SHM_ALL
$SYST net.ipv4.ip_forward=1
$SYST net.ipv4.conf.all.accept_source_route=0
$SYST net.ipv4.conf.all.accept_redirects=0
$SYST net.ipv4.conf.all.send_redirects=0
$SYST net.ipv4.conf.all.rp_filter=0
$SYST net.ipv4.conf.default.accept_source_route=0
$SYST net.ipv4.conf.default.accept_redirects=0
$SYST net.ipv4.conf.default.send_redirects=0
$SYST net.ipv4.conf.default.rp_filter=0
# $SYST net.ipv4.conf.eth0.send_redirects=0
# $SYST net.ipv4.conf.eth0.rp_filter=0

#clear iptables rules
# iptables -F
# iptables -X
# iptables -F -t nat
# iptables -X -t nat
# Create IPTables rules
# iptables -I INPUT 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
# iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP
# iptables -I INPUT 3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# iptables -I INPUT 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
# iptables -I INPUT 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
# iptables -I INPUT 6 -p udp --dport 1701 -j DROP
# iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
iptables -D FORWARD -i "$L2TP_FORWARD_NIC" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD 2 -i "$L2TP_FORWARD_NIC" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -D FORWARD -i ppp+ -o "$L2TP_FORWARD_NIC" -j ACCEPT
iptables -I FORWARD 3 -i ppp+ -o "$L2TP_FORWARD_NIC" -j ACCEPT
iptables -D FORWARD -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j ACCEPT
iptables -I FORWARD 4 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j ACCEPT
# iptables -I FORWARD 5 -i "$L2TP_FORWARD_NIC" -d "$XAUTH_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# iptables -I FORWARD 6 -s "$XAUTH_NET" -o "$L2TP_FORWARD_NIC" -j ACCEPT
# Uncomment if you wish to disallow traffic between VPN clients themselves
iptables -D FORWARD -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j DROP
iptables -I FORWARD 2 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j DROP
# iptables -I FORWARD 3 -s "$XAUTH_NET" -d "$XAUTH_NET" -j DROP
#iptables -A FORWARD -j DROP
#iptables -t nat -I POSTROUTING -s "$XAUTH_NET" -o "$L2TP_FORWARD_NIC" -m policy --dir out --pol none -j MASQUERADE
iptables -t nat -D POSTROUTING -s "$L2TP_NET" -o "$L2TP_FORWARD_NIC" -j MASQUERADE
iptables -t nat -I POSTROUTING -s "$L2TP_NET" -o "$L2TP_FORWARD_NIC" -j MASQUERADE

# Update file attributes
chmod 600 /etc/ipsec.secrets /etc/ppp/chap-secrets /etc/ipsec.d/passwd

# Start services
mkdir -p /run/pluto /var/run/pluto /var/run/xl2tpd
rm -f /run/pluto/pluto.pid /var/run/pluto/pluto.pid /var/run/xl2tpd.pid

/usr/local/sbin/ipsec start
/usr/sbin/xl2tpd -c /etc/xl2tpd/xl2tpd.conf

cat <<EOF
================================================
IPsec VPN server is now ready for use!
Connect to your new VPN with these details:
Server IP: $PUBLIC_IP
EOF

#log process
service rsyslog restart
service ipsec restart
sed -i '/pluto\.pid/a service rsyslog restart' /opt/src/run.sh

cat <<EOF
================================================
Vpn server start listen vpn connections change event...
Report vpn connections info to nerv vpn server:$REPORTER_ADDR
Time interval:$REPORTER_INTERVAL
EOF

function add_conn(){
    echo "start add vpn connection:${1}"
    conn_name=$(cat /opt/src/nerv/conn_${1}_name)
    conn_nervconntype=$(cat /opt/src/nerv/conn_${1}_nervconntype)
    conn_right=$(cat /opt/src/nerv/conn_${1}_right)
    conn_also=$(cat /opt/src/nerv/conn_${1}_also)
    conn_auto=$(cat /opt/src/nerv/conn_${1}_auto)
    conn_leftprotoport=$(cat /opt/src/nerv/conn_${1}_leftprotoport)
    conn_rightprotoport=$(cat /opt/src/nerv/conn_${1}_rightprotoport)
    conn_type=$(cat /opt/src/nerv/conn_${1}_type)
    conn_phase2=$(cat /opt/src/nerv/conn_${1}_phase2)
    conn_leftsubnet=$(cat /opt/src/nerv/conn_${1}_leftsubnet)
    conn_leftsourceip=$(cat /opt/src/nerv/conn_${1}_leftsourceip)
    conn_rightsubnet=$(cat /opt/src/nerv/conn_${1}_rightsubnet)
    conn_rightsourceip=$(cat /opt/src/nerv/conn_${1}_rightsourceip)
    conn_psk=$(cat /opt/src/nerv/conn_${1}_psk)
    conn_login_user_name=$(cat /opt/src/nerv/conn_${1}_login_user_name)
    conn_login_user_password=$(cat /opt/src/nerv/conn_${1}_login_user_password)
    cp /opt/src/nerv/conn_${1}_right /opt/src/bak/conn_${1}_right_bak
    cp /opt/src/nerv/conn_${1}_psk /opt/src/bak/conn_${1}_psk_bak
    cp /opt/src/nerv/conn_${1}_login_user_name /opt/src/bak/conn_${1}_login_user_name_bak
    cp /opt/src/nerv/conn_${1}_login_user_password /opt/src/bak/conn_${1}_login_user_password_bak

    #generate vpn conn config file
    conn_file=/opt/src/ipsec_nerv_${1}.conf
cat > $conn_file <<EOF
conn shared
  left=%defaultroute
  leftid=$PUBLIC_IP
  encapsulation=yes
  authby=secret
  pfs=no
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
  ikev2=never
  ike=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,aes256-sha2;modp1024,aes128-sha1;modp1024
  phase2alg=aes_gcm-null,aes128-sha1,aes256-sha1,aes256-sha2_512,aes128-sha2,aes256-sha2
EOF
    echo "conn ${1}" >> $conn_file
    if [ "$conn_nervconntype" == "IPSEC/L2TP" ]; then
      echo "  right=%any" >> $conn_file
    else
      echo "  right=$conn_right" >> $conn_file
    fi
    if [ ! -z "$conn_right" ]; then
      echo "  rightid=$conn_right" >> $conn_file
    fi
    if [ ! -z "$conn_auto" ]; then
      echo "  auto=$conn_auto" >> $conn_file
    fi
    if [ ! -z "$conn_leftprotoport" ]; then
      echo "  leftprotoport=$conn_leftprotoport" >> $conn_file
    fi
    if [ ! -z "$conn_rightprotoport" ]; then
      echo "  rightprotoport=$conn_rightprotoport" >> $conn_file
    fi
    if [ ! -z "$conn_type" ]; then
      echo "  type=$conn_type" >> $conn_file
    fi
    if [ ! -z "$conn_phase2" ]; then
      echo "  phase2=$conn_phase2" >> $conn_file
    fi
    if [ ! -z "$conn_also" ]; then
      echo "  also=$conn_also" >> $conn_file
    else
      echo "  also=shared" >> $conn_file
    fi
    if [ ! -z "$conn_leftsubnet" ]; then
      echo "  leftsubnet=$conn_leftsubnet" >> $conn_file
    fi
    if [ -z "$conn_leftsourceip" ]; then
      routeInfo=`ip route | grep $conn_leftsubnet`
      routeInfoArray=(${routeInfo// / })
      conn_leftsourceip=${routeInfoArray[-1]}
    fi
    if [ ! -z "$conn_leftsourceip" ]; then
      echo "  leftsourceip=$conn_leftsourceip" >> $conn_file
    fi
    if [ ! -z "$conn_rightsubnet" ]; then
      echo "  rightsubnet=$conn_rightsubnet" >> $conn_file
    fi
    if [ ! -z "$conn_rightsourceip" ]; then
      echo "  rightsourceip=$conn_rightsourceip" >> $conn_file
    fi

    #print connection info
    echo "${1} name: $conn_name"
    echo "${1} nervconntype: $conn_nervconntype"
    echo "${1} right_id: $conn_right"
    echo "${1} also: $conn_also"
    echo "${1} auto: $conn_auto"
    echo "${1} leftprotoport: $conn_leftprotoport"
    echo "${1} rightprotoport: $conn_rightprotoport"
    echo "${1} type: $conn_type"
    echo "${1} phase2: $conn_phase2"
    echo "${1} leftsubnet: $conn_leftsubnet"
    echo "${1} leftsourceip: $conn_leftsourceip"
    echo "${1} rightsubnet: $conn_rightsubnet"
    echo "${1} rightsourceip: $conn_rightsourceip"
    echo "${1} psk: $conn_psk"
    echo "${1} login user name: $conn_login_user_name"
    echo "${1} login user password: $conn_login_user_password"

    #appen psk to /etc/ipsec.secrets
    if [ "$conn_nervconntype" == "IPSEC/L2TP" ]; then
      if [ ! -z "$conn_psk" ]; then
        echo "$PUBLIC_IP $conn_right : PSK \"$conn_psk\"" >> /etc/ipsec.secrets
      fi
    else
      if [ ! -z "$conn_psk" ]; then
        sed -i "1a $PUBLIC_IP $conn_right : PSK \"$conn_psk\"" /etc/ipsec.secrets
      fi
    fi

    #add ip forward rule
    if [ ! -z "$conn_leftsubnet" ] && [ ! -z "$conn_rightsubnet" ] && [ "$conn_rightsubnet" != "vhost:%priv" ]; then
      #下面两条规则是避免流量被k8s和docker的iptables规则干掉，先删除是避免创建重复的规则
      #对于left删除可能导致已有流量瞬时断开
      iptables -D FORWARD -s $conn_leftsubnet -d 0.0.0.0/0 -j ACCEPT
      iptables -I FORWARD -s $conn_leftsubnet -d 0.0.0.0/0 -j ACCEPT
      iptables -D FORWARD -s $conn_rightsubnet -d 0.0.0.0/0 -j ACCEPT
      iptables -I FORWARD -s $conn_rightsubnet -d 0.0.0.0/0 -j ACCEPT
      #转发规则
      iptables -t nat -A POSTROUTING -s 172.16.29.0/24 -j MASQUERADE
    fi
     #add pppd login config
    if [ ! -z "$conn_login_user_name" ] && [ ! -z "$conn_login_user_password" ] &&  [ "$conn_nervconntype" == "IPSEC/L2TP" ]; then
      echo "\"$conn_login_user_name\" * \"$conn_login_user_password\" *" >> /etc/ppp/chap-secrets
      xl2tpd -s /etc/ppp/chap-secrets
    fi
    #ipsec start connections
    ipsec addconn ${1} --config $conn_file
    ipsec auto --rereadsecrets
    echo "add vpn connection:${1} success"
    #report to manager
    curl -s --location --request POST "$REPORTER_ADDR/ConnCreate" \
    --header "NERV-TOKEN: $REPORTER_TOKEN" \
    --header 'Content-Type: text/plain' \
    --data-raw "{
        \"vpn\":\"$VPN_KUBE_UUID\",
        \"connInnerName\":\"${1}\"
    }"
}

function del_conn(){
    echo "start delete vpn connection:${1}"
    #delete vpn conn config file
    conn_file=/opt/src/ipsec_nerv_${1}.conf
    rm -f $conn_file
    #delete psk in /etc/ipsec.secrets
    rightt=$(cat /opt/src/bak/conn_${1}_right_bak)
    pskk=$(cat /opt/src/bak/conn_${1}_psk_bak)
    userr=$(cat /opt/src/bak/conn_${1}_login_user_name_bak)
    pwdd=$(cat /opt/src/bak/conn_${1}_login_user_password_bak)
    #del psk
    sed -i "/$PUBLIC_IP $rightt : PSK/d" /etc/ipsec.secrets
    #delete pppd login config
    sed -i "0,/\"$conn_login_user_name\" \* \"$conn_login_user_password\" \*/d" /etc/ppp/chap-secrets
    xl2tpd -s /etc/ppp/chap-secrets
    #
    rm -f /opt/src/bak/conn_${1}_right_bak
    rm -f /opt/src/bak/conn_${1}_psk_bak
    rm -f /opt/src/bak/conn_${1}_login_user_name_bak
    rm -f /opt/src/bak/conn_${1}_login_user_password_bak
    #ipsec delete connections
    ipsec auto --delete ${1}
    ipsec auto --rereadsecrets
    echo "delete vpn connection:${1} success"
    #report to manager
    curl -s --location --request POST "$REPORTER_ADDR/ConnDelete" \
    --header "NERV-TOKEN: $REPORTER_TOKEN" \
    --header 'Content-Type: text/plain' \
    --data-raw "{
        \"vpn\":\"$VPN_KUBE_UUID\",
        \"connInnerName\":\"${1}\"
    }"
}

function update_conns(){
    NEW_IPSEC_CONNS_STR=$(cat /opt/src/nerv/VPN_IPSEC_CONNS)
    if [ "$NEW_IPSEC_CONNS_STR" != "$IPSEC_CONNS_STR" ];then
        echo "Got a vpn connections change event, start processing..."
        NEW_IPSEC_CONN_ARRAY=(${NEW_IPSEC_CONNS_STR//,/ })
        #find new connections
        for new_ele in ${NEW_IPSEC_CONN_ARRAY[*]}
        do
            is_new_conn=1
            for old_ele in ${IPSEC_CONN_ARRAY[*]}
            do
                if [ "$new_ele" == "$old_ele" ];then
                    is_new_conn=0
                    break
                fi
            done
            if [ $is_new_conn == 1 ];then
                add_conn $new_ele
            fi
        done
        #find deleted connections
        for old_ele in ${IPSEC_CONN_ARRAY[*]}
        do
            is_deleted_conn=1
            for new_ele in ${NEW_IPSEC_CONN_ARRAY[*]}
            do
                if [ "$new_ele" == "$old_ele" ];then
                    is_deleted_conn=0
                    break
                fi
            done
            if [ $is_deleted_conn == 1 ];then
                del_conn $old_ele
            fi
        done
        #record conn status for next comparison
        IPSEC_CONNS_STR=$NEW_IPSEC_CONNS_STR
        IPSEC_CONN_ARRAY=(${IPSEC_CONNS_STR//,/ })
    fi
}

#找到当前所有连接
IPSEC_CONNS_STR=${VPN_IPSEC_CONNS}
IPSEC_CONN_ARRAY=(${IPSEC_CONNS_STR//,/ })
for ele in ${IPSEC_CONN_ARRAY[*]}
do
    add_conn $ele
done



while [ true ]; do
#update ipsec conn
update_conns

#report vpn info
if [ ! -z "$REPORTER_ADDR" ]; then
/bin/sleep $REPORTER_INTERVAL
connstatus=`ipsec whack --trafficstatus | tr "\n" ";"`
#
connstatus=${connstatus//\\n/";"}
connstatus=${connstatus//\"/""}
connstatus=${connstatus//\,/""}
connstatus=${connstatus//\:/""}
connstatus=${connstatus//[/" "}
connstatus=${connstatus//]/""}

curl -s --location --request POST "$REPORTER_ADDR" \
--header "NERV-TOKEN: $REPORTER_TOKEN" \
--header 'Content-Type: text/plain' \
--data-raw "{
    \"vpn\":\"$VPN_KUBE_UUID\",
    \"status\":\"$connstatus\"
}"
fi

done

