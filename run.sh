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

# Remove whitespace and quotes around VPN variables, if any
VPN_IPSEC_PSK=$(nospaces "$VPN_DEFAULT_PSK")
VPN_IPSEC_PSK=$(noquotes "$VPN_DEFAULT_PSK")
VPN_USER=$(nospaces "$VPN_DEFAULT_USER")
VPN_USER=$(noquotes "$VPN_DEFAULT_USER")
VPN_PASSWORD=$(nospaces "$VPN_DEFAULT_PASSWORD")
VPN_PASSWORD=$(noquotes "$VPN_DEFAULT_PASSWORD")


if printf '%s' "$VPN_DEFAULT_PSK $VPN_DEFAULT_USER $VPN_DEFAULT_PASSWORD" | LC_ALL=C grep -q '[^ -~]\+'; then
  exiterr "VPN credentials must not contain non-ASCII characters."
fi

case "$VPN_DEFAULT_PSK $VPN_DEFAULT_USER $VPN_DEFAULT_PASSWORD" in
  *[\\\"\']*)
    exiterr "VPN credentials must not contain these special characters: \\ \" '"
    ;;
esac

if printf '%s' "$VPN_DEFAULT_USER" | tr ' ' '\n' | sort | uniq -c | grep -qv '^ *1 '; then
  exiterr "VPN usernames must not contain duplicates."
fi

echo
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
  uniqueids=no

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

#添加所有conn配置，添加到配置文件里面
IPSEC_CONNS_STR=${VPN_IPSEC_CONNS}
IPSEC_CONN_ARRAY=(${IPSEC_CONNS_STR//,/ })

for element in ${IPSEC_CONN_ARRAY[*]}
do
echo "get an ipsec conn name:${element}"
conn_name=`eval echo '$'"conn_${element}_name"`
conn_right=`eval echo '$'"conn_${element}_right"`
conn_also=`eval echo '$'"conn_${element}_also"`
conn_auto=`eval echo '$'"conn_${element}_auto"`
conn_leftprotoport=`eval echo '$'"conn_${element}_leftprotoport"`
conn_rightprotoport=`eval echo '$'"conn_${element}_rightprotoport"`
conn_type=`eval echo '$'"conn_${element}_type"`
conn_phase2=`eval echo '$'"conn_${element}_phase2"`
conn_also=`eval echo '$'"conn_${element}_also"`
conn_leftsubnet=`eval echo '$'"conn_${element}_leftsubnet"`
conn_rightsubnet=`eval echo '$'"conn_${element}_rightsubnet"`
conn_psk=`eval echo '$'"conn_${element}_psk"`
#add nat conn
echo "conn $conn_name" >> /etc/ipsec.conf
echo "  right=%any" >> /etc/ipsec.conf
if [ ! -z "$conn_right" ]; then
  echo "  rightid=$conn_right" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_auto" ]; then
  echo "  auto=$conn_auto" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_leftprotoport" ]; then
  echo "  leftprotoport=$conn_leftprotoport" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_rightprotoport" ]; then
  echo "  rightprotoport=$conn_rightprotoport" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_type" ]; then
  echo "  type=$conn_type" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_phase2" ]; then
  echo "  phase2=$conn_phase2" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_also" ]; then
  echo "  also=$conn_also" >> /etc/ipsec.conf
else
  echo "  also=shared" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_leftsubnet" ]; then
  echo "  leftsubnet=$conn_leftsubnet" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_rightsubnet" ]; then
  echo "  rightsubnet=$conn_rightsubnet" >> /etc/ipsec.conf
fi
#add no nat conn
echo "conn $conn_name-noNAT" >> /etc/ipsec.conf
echo "  right=%any" >> /etc/ipsec.conf
if [ ! -z "$conn_right" ]; then
  echo "  rightid=$conn_right" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_auto" ]; then
  echo "  auto=$conn_auto" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_leftprotoport" ]; then
  echo "  leftprotoport=$conn_leftprotoport" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_rightprotoport" ]; then
  echo "  rightprotoport=$conn_rightprotoport" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_type" ]; then
  echo "  type=transport" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_also" ]; then
  echo "  also=$conn_also" >> /etc/ipsec.conf
else
  echo "  also=shared" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_leftsubnet" ]; then
  echo "  leftsubnet=$conn_leftsubnet" >> /etc/ipsec.conf
fi
if [ ! -z "$conn_rightsubnet" ]; then
  echo "  rightsubnet=$conn_rightsubnet" >> /etc/ipsec.conf
fi

if [ ! -z "$conn_psk" ]; then
  echo "$PUBLIC_IP $conn_right : PSK \"$conn_psk\"" >> /etc/ipsec.secrets
fi

done

# Specify default IPsec PSK
echo "$PUBLIC_IP %any : PSK \"$VPN_DEFAULT_PSK\"" >> /etc/ipsec.secrets

# Create xl2tpd config
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
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
cat > /etc/ppp/chap-secrets <<EOF
"$VPN_DEFAULT_USER" * "$VPN_DEFAULT_PASSWORD" *
EOF

VPN_PASSWORD_ENC=$(openssl passwd -1 "$VPN_DEFAULT_PASSWORD")
cat > /etc/ipsec.d/passwd <<EOF
$VPN_DEFAULT_USER:$VPN_DEFAULT_PASSWORD_ENC:xauth-psk
EOF

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
$SYST net.ipv4.conf.eth0.send_redirects=0
$SYST net.ipv4.conf.eth0.rp_filter=0

# Create IPTables rules
iptables -I INPUT 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
iptables -I INPUT 2 -m conntrack --ctstate INVALID -j DROP
iptables -I INPUT 3 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
iptables -I INPUT 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
iptables -I INPUT 6 -p udp --dport 1701 -j DROP
iptables -I FORWARD 1 -m conntrack --ctstate INVALID -j DROP
iptables -I FORWARD 2 -i "$L2TP_FORWARD_NIC" -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I FORWARD 3 -i ppp+ -o "$L2TP_FORWARD_NIC" -j ACCEPT
iptables -I FORWARD 4 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j ACCEPT
# iptables -I FORWARD 5 -i "$L2TP_FORWARD_NIC" -d "$XAUTH_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# iptables -I FORWARD 6 -s "$XAUTH_NET" -o "$L2TP_FORWARD_NIC" -j ACCEPT
# Uncomment if you wish to disallow traffic between VPN clients themselves
iptables -I FORWARD 2 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j DROP
# iptables -I FORWARD 3 -s "$XAUTH_NET" -d "$XAUTH_NET" -j DROP
iptables -A FORWARD -j DROP
#iptables -t nat -I POSTROUTING -s "$XAUTH_NET" -o "$L2TP_FORWARD_NIC" -m policy --dir out --pol none -j MASQUERADE
iptables -t nat -I POSTROUTING -s "$L2TP_NET" -o "$L2TP_FORWARD_NIC" -j MASQUERADE

# Update file attributes
chmod 600 /etc/ipsec.secrets /etc/ppp/chap-secrets /etc/ipsec.d/passwd

cat <<EOF
================================================
IPsec VPN server is now ready for use!
Connect to your new VPN with these details:
Server IP: $PUBLIC_IP
IPsec PSK Any: $VPN_DEFAULT_PSK
Username: $VPN_DEFAULT_USER
Password: $VPN_DEFAULT_PASSWORD
EOF

# Start services
mkdir -p /run/pluto /var/run/pluto /var/run/xl2tpd
rm -f /run/pluto/pluto.pid /var/run/pluto/pluto.pid /var/run/xl2tpd.pid

/usr/local/sbin/ipsec start
/usr/sbin/xl2tpd -c /etc/xl2tpd/xl2tpd.conf

#log
service rsyslog restart
service ipsec restart
sed -i '/pluto\.pid/a service rsyslog restart' /opt/src/run.sh

cat <<EOF
================================================
Start report status to nerv vpn server
EOF

while [ true ]; do
/bin/sleep 10
connstatus=`ipsec whack --trafficstatus`
#
connstatus=${connstatus//\"/" "}
connstatus=${connstatus//\,/" "}
connstatus=${connstatus//\:/" "}
connstatus=${connstatus//[/" "}
connstatus=${connstatus//]/" "}
connstatus=${connstatus//" "/";"}

echo $connstatus

curl --location --request POST 'http://100.73.142.78:5547/api/objs/VpnConnectionStatusReport' \
--header 'NERV-TOKEN: 72e9ff31a36f9694601d2ec77a8007f7' \
--header 'Content-Type: text/plain' \
--data-raw "{
    \"vpn\":\"$VPN_DEFAULT_PSK\",
    \"status\":\"$connstatus\"
}"
done