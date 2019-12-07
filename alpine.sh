#!/bin/sh -e

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root" 1>&2
	exit 1
fi

dev=""
mount_dir=/mnt/alpine

set_hostname="$1"
set_address="$2"
set_netmask="$3"
set_gateway="$4"

public_ip=$(wget --no-check-certificate -4 -qO- http://ifconfig.co)
auto_hostname="alpine-""${public_ip//./-}"

if [ -b /dev/vda ]
then
	dev=/dev/vda
elif [ -b /dev/sda ]
then
	dev=/dev/sda
else
	echo /dev/vda or /dev/sda not exist.
	exit 2
fi

echo
echo =====================================
echo Install Alpine Linux edge to $dev.
echo =====================================
echo

echo Format $dev ...
mkfs.ext4 -L alpine-root -b 1024 -I 128 -O "^has_journal" $dev

echo Mount $dev to ${mount_dir} ...
mkdir -p ${mount_dir}
mount $dev ${mount_dir}

echo Download apk-tools-static ...
ver=$(wget -qO- https://pkgs.alpinelinux.org/package/edge/main/x86/apk-tools-static | awk -F'>' '/Flagged:/ {sub(/<\/a/,"",$2);print$2}')
wget -qO- http://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/apk-tools-static-$ver.apk | tar -xz -C /tmp

echo Install alpine-base to ${mount_dir} ...
/tmp/sbin/apk.static -X http://dl-cdn.alpinelinux.org/alpine/edge/main -U --allow-untrusted --root ${mount_dir} --initdb add alpine-base syslinux linux-virt dropbear

echo Install V2ray ...
VER=$(wget --no-check-certificate -q -O- https://api.github.com/repos/v2ray/v2ray-core/releases/latest | awk -F'"' '/tag_name/ {print $4}')
URL=https://github.com/v2ray/v2ray-core/releases/download/$VER/v2ray-linux-64.zip
wget --no-check-certificate -q -O- $URL | unzip - -q -d ${mount_dir}/usr/sbin v2ray v2ctl
chmod +x ${mount_dir}/usr/sbin/{v2ray,v2ctl}

UUID=$(wget --no-check-certificate -qO- https://www.uuidgenerator.net/api/version4)
mkdir ${mount_dir}/etc/v2ray
cat << EOF > ${mount_dir}/etc/v2ray/config.json
{
  "log": {
    "loglevel": "none"
  },
  "inbounds": [{
    "port": 9119,
    "protocol": "vmess",
    "settings": {
      "clients": [{
        "id": "$UUID"
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

cat << EOF > ${mount_dir}/etc/init.d/v2ray
#!/sbin/openrc-run

name="V2Ray Server"
command="/usr/sbin/v2ray"
command_args="-config /etc/v2ray/config.json"
command_background=yes
command_user=nobody:nobody
pidfile="/var/run/v2ray.pid"

depend() {
	need net localmount
	after firewall
}
EOF

echo Config system ...
mount /dev ${mount_dir}/dev --bind
mount -o remount,ro,bind ${mount_dir}/dev

mount -t proc none ${mount_dir}/proc
mount -o bind /sys ${mount_dir}/sys

[[ -n "$set_hostname" ]] && echo "$set_hostname" > ${mount_dir}/etc/hostname || echo "$auto_hostname" > ${mount_dir}/etc/hostname
echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > ${mount_dir}/etc/resolv.conf
echo tcp_bbr >> ${mount_dir}/etc/modules
echo -e "http://dl-cdn.alpinelinux.org/alpine/edge/main\nhttp://dl-cdn.alpinelinux.org/alpine/edge/community\nhttp://dl-cdn.alpinelinux.org/alpine/edge/testing" > ${mount_dir}/etc/apk/repositories

mkdir -p $(mount_dir)/root/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM0uVU4ScS9bSJ+AGr25Dz96yBDTBDzVzIdAArJE0Uki" >> ${mount_dir}/root/.ssh/authorized_keys
chmod 600 ${mount_dir}/root/.ssh/authorized_keys

cat << EOF > ${mount_dir}/etc/inittab
::sysinit:/sbin/openrc sysinit
::sysinit:/sbin/openrc boot
::wait:/sbin/openrc default
tty1::respawn:/sbin/getty 38400 tty1
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/openrc shutdown
EOF

if [ -n "$set_address" -o -n "$set_netmask" -o -n "$set_gatway" ]
then
	cat << EOF > ${mount_dir}/etc/network/interfaces
	auto lo
	iface lo inet loopback
	
	auto eth0
	iface eth0 inet static
		address "$set_address"
		netmask "$set_netmask"
		gateway "$set_gatway"
	EOF
else
	cat << EOF > ${mount_dir}/etc/network/interfaces
	auto lo
	iface lo inet loopback
	
	auto eth0
	iface eth0 inet dhcp
	EOF
fi

cat << EOF > ${mount_dir}/etc/fstab
LABEL=alpine-root /    ext4  defaults,noatime                            0 0
tmpfs             /tmp tmpfs mode=1777,strictatime,nosuid,nodev,size=90% 0 0
EOF

cat << EOF > ${mount_dir}/etc/sysctl.d/10-tcp_bbr.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

cat << EOF > ${mount_dir}/etc/sysctl.d/20-security.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 5
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_echo_ignore_all = 1
EOF

cat << EOF > ${mount_dir}/etc/update-extlinux.conf
overwrite=1
vesa_menu=0
default_kernel_opts="ipv6.disable=1 quiet rootfstype=ext4"
modules=ext4
root=LABEL=alpine-root
verbose=0
timeout=0
hidden=0
EOF

cat << EOF > ${mount_dir}/etc/conf.d/dropbear
DROPBEAR_OPTS="-s -p 127.0.0.1"
EOF

chroot ${mount_dir} /bin/sh -c '
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
echo root:Alpine#123 | chpasswd
#apk update
#apk add linux-virt
#dd bs=440 count=1 if=/usr/share/syslinux/mbr.bin of=/dev/sda
#extlinux -i /boot
#update-extlinux

rc-update add devfs sysinit
rc-update add hwdrivers sysinit
rc-update add mdev sysinit
rc-update add modules boot
rc-update add sysctl boot
rc-update add hostname boot
rc-update add bootmisc boot
rc-update add syslog boot
rc-update add networking boot
rc-update add urandom boot
rc-update add dropbear
rc-update add mount-ro shutdown
rc-update add killprocs shutdown
'

umount $(mount_dir)

echo Done, Rebooting
sync
sync
sync
reboot
