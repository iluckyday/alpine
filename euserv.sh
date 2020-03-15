#!/bin/bash -e

# do first
#
# echo -e "nameserver 2001:67c:2b0::4\nnameserver 2001:67c:27e4::64" > /etc/resolv.conf
#
# wget -qO /run/euserv.sh https://raw.githubusercontent.com/iluckyday/vps/master/euserv.sh && chmod +x /run/euserv.sh && /run/euserv.sh <domain> <mail> [UUID]

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root"
	exit 1
fi

if [ $# -lt 2 ]
then
	echo "Atleast two arguments needed: domain mail [uuid]."
	exit 1
fi

domain=$1
mail=$2
uuid=$3

echo install v2ray ...
VER=$(wget --no-check-certificate -qO- https://api.github.com/repos/v2ray/v2ray-core/releases/latest | awk -F'"' '/tag_name/ {print $4}')
URL=https://github.com/v2ray/v2ray-core/releases/download/$VER/v2ray-linux-64.zip
wget --no-check-certificate -qO- $URL | busybox unzip - -o -d /usr/sbin v2ray v2ctl
chmod +x /usr/sbin/{v2ray,v2ctl}

cat << EOF > /etc/v2ray.json
{
  "log": {
    "loglevel": "none"
  },
  "inbounds": [  {
    "port": 1024,
    "listen": "127.0.0.1",
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "${uuid:-35d169dc-ae92-f3bf-d84e-c23f4d197b1e}",
        "alterId": 100
      }]
    },
    "streamSettings": {
      "network": "ws"
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF

cat << EOF > /etc/systemd/system/v2ray.service
[Unit]
Description=V2Ray Server
After=network.target

[Service]
DynamicUser=yes
ProtectHome=yes
NoNewPrivileges=yes
ExecStart=/usr/sbin/v2ray -config /etc/v2ray.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo install caddy ...
pkgver=$(wget -qO- https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=caddy-bin | awk -F'=' '/^pkgver/ {print $2}')
caddyurl="https://github.com/mholt/caddy/releases/download/v${pkgver//_/-}/caddy_v${pkgver//_/-}_linux_amd64.tar.gz"
wget -qO- "$caddyurl" | tar -xz -C /usr/sbin caddy
chmod +x /usr/sbin/caddy

cat << EOF > /etc/systemd/system/caddy.service
[Unit]
Description=Caddy HTTP/2 web server
After=network.target

[Service]
ExecStart=/usr/sbin/caddy -log stdout -agree -conf /etc/caddy.conf
ExecReload=/usr/bin/kill -USR1 $MAINPID
LimitNOFILE=1048576
LimitNPROC=64
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/caddy.conf
$domain {
  tls $mail
  header / -Server
  proxy / 127.0.0.1:1024 {
    websocket
  }
}
EOF

echo 'export HISTSIZE=1000 LESSHISTFILE=/dev/null HISTFILE=/dev/null' >> .bashrc
echo -e "nameserver 2001:67c:2b0::4\nnameserver 2001:67c:27e4::64" > /etc/resolv.conf
mkdir -p /root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDyuzRtZAyeU3VGDKsGk52rd7b/rJ/EnT8Ce2hwWOZWp" > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

cat << EOF > /etc/sysctl.d/20-security.conf
net.ipv6.tcp_syncookies = 1
net.ipv6.tcp_synack_retries = 5
net.ipv6.tcp_syncookies = 1
net.ipv6.icmp_ignore_bogus_error_responses=1
net.ipv6.icmp_echo_ignore_all = 1
EOF

systemctl enable v2ray caddy
systemctl mask cron.service rsyslog.service apt-daily-upgrade.timer apt-daily.timer logrotate.timer

sed -i 's/#ListenAddress 0.0.0.0/ListenAddress 127.0.0.1/g' /etc/ssh/sshd_config
rm -f /root/.bash_history

echo done, reboot.
sleep 2
reboot
